package com.captiveportal.printserver.controller;

import com.captiveportal.printserver.config.CaptivePortalProperties;
import com.captiveportal.printserver.exception.FileValidationException;
import com.captiveportal.printserver.exception.PrintException;
import com.captiveportal.printserver.security.FileValidationService;
import com.captiveportal.printserver.security.NetworkSecurityManager;
import com.captiveportal.printserver.service.PrintService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/**
 * PrintController — Secure {@code POST /api/print} endpoint for the Captive Portal.
 *
 * <h2>Request lifecycle</h2>
 * <pre>
 *  Client POST (multipart/form-data, file=<pdf>)
 *    │
 *    ├─ 1. Extract real client IP  (X-Forwarded-For stripped, using socket IP)
 *    ├─ 2. FileValidationService.validateAndReadToMemory()   ← 7-layer validation
 *    ├─ 3. PrintService.printAndWipe()                       ← print + zero bytes
 *    ├─ 4. NetworkSecurityManager.disconnectImmediately()    ← OS-level eviction
 *    └─ 5. Return 200 OK with JSON success payload
 *
 *  On any failure → bytes wiped, error logged, HTTP error returned (no leakage)
 * </pre>
 *
 * <h2>Security decisions</h2>
 * <ul>
 *   <li>The real client IP is taken from {@code HttpServletRequest.getRemoteAddr()}, NOT
 *       from {@code X-Forwarded-For}. In a captive-portal context there is no reverse
 *       proxy, so the socket IP is authoritative. Trusting X-Forwarded-For would allow
 *       a client to spoof their own IP to avoid disconnection.</li>
 *   <li>Error responses never echo back user input or internal exception messages;
 *       they return safe, generic strings.</li>
 *   <li>Rate limiting: a client that fails validation is still registered for eviction
 *       (they are already connected to the hotspot at this point).</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class PrintController {

    private static final Logger log = LoggerFactory.getLogger(PrintController.class);

    private final FileValidationService fileValidationService;
    private final PrintService printService;
    private final NetworkSecurityManager networkSecurityManager;
    private final CaptivePortalProperties props;

    @Autowired
    public PrintController(
            FileValidationService fileValidationService,
            PrintService printService,
            NetworkSecurityManager networkSecurityManager,
            CaptivePortalProperties props) {
        this.fileValidationService = fileValidationService;
        this.printService = printService;
        this.networkSecurityManager = networkSecurityManager;
        this.props = props;
    }

    /**
     * Accepts a PDF upload, validates it, prints it, and disconnects the client.
     *
     * @param file    the uploaded multipart file (must be a valid PDF ≤ 10 MB)
     * @param request the HTTP request (for IP extraction and client registration)
     * @return 200 with success JSON, or 400/413/500 with safe error JSON
     */
    @PostMapping(
        value = "/print",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> handlePrint(
            @RequestParam("file") MultipartFile file,
            HttpServletRequest request) {

        String clientIp = extractRealClientIp(request);
        log.info("Print request received from IP={} at {}", clientIp, Instant.now());

        // Register client for session-timeout eviction as soon as we see them.
        // Even if validation fails, they are on the hotspot and must be evicted.
        // registerClient() is idempotent — calling it multiple times is safe.
        networkSecurityManager.registerClient(clientIp, resolveClientMac(clientIp));

        // ── Step 1: Validate the uploaded file ────────────────────────────────
        byte[] pdfBytes = null;
        try {
            pdfBytes = fileValidationService.validateAndReadToMemory(file);
        } catch (FileValidationException e) {
            log.warn("Validation REJECTED from IP={}: {}", clientIp, e.getMessage());
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorBody("File validation failed. Only valid PDFs under 10 MB are accepted."));
        } catch (IOException e) {
            log.error("IO error reading upload from IP={}: {}", clientIp, e.getMessage());
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorBody("Could not read uploaded file. Please try again."));
        }

        // Validate size boundary once more — belt-and-suspenders
        if (pdfBytes.length > props.getMaxPdfSizeBytes()) {
            FileValidationService.wipeBytes(pdfBytes);
            log.warn("Post-read size violation from IP={}. Rejecting.", clientIp);
            return ResponseEntity
                .status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(errorBody("File exceeds the 10 MB size limit."));
        }

        // ── Step 2: Print and wipe ────────────────────────────────────────────
        // NOTE: printAndWipe() ALWAYS zeroes pdfBytes in its finally block.
        // We must NOT reference pdfBytes after this call.
        try {
            printService.printAndWipe(pdfBytes);
            // pdfBytes is now zeroed — do not use it further
        } catch (PrintException e) {
            // pdfBytes was already wiped inside printAndWipe's finally block
            log.error("Print FAILED for IP={}: {}", clientIp, e.getMessage());
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorBody("Print job could not be completed. Please contact staff."));
        }

        // ── Step 3: Disconnect client ─────────────────────────────────────────
        log.info("Print successful for IP={}. Initiating immediate network disconnection.", clientIp);
        networkSecurityManager.disconnectImmediately(clientIp);

        // ── Step 4: Return success ────────────────────────────────────────────
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Your document has been sent to the printer. You will now be disconnected.",
            "timestamp", Instant.now().toString()
        ));
    }

    /**
     * Health-check endpoint for the admin panel.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of(
            "status", "running",
            "activeSessions", networkSecurityManager.activeSessionCount(),
            "timestamp", Instant.now().toString()
        ));
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * Extracts the real client IP from the servlet request socket.
     * Intentionally ignores X-Forwarded-For to prevent IP spoofing in the
     * captive-portal context (there is no trusted reverse proxy).
     */
    private String extractRealClientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    /**
     * Attempts to resolve the MAC address of a given IP using the OS ARP cache.
     * Returns "unknown" if resolution fails — the NetworkSecurityManager will
     * fall back to IP-only blocking in that case.
     */
    private String resolveClientMac(String clientIp) {
        try {
            boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
            String[] cmd = isWindows
                ? new String[]{"arp", "-a", clientIp}
                : new String[]{"arp", "-n", clientIp};

            Process proc = Runtime.getRuntime().exec(cmd);
            String output;
            try (java.io.BufferedReader reader =
                     new java.io.BufferedReader(new java.io.InputStreamReader(proc.getInputStream()))) {
                output = reader.lines().collect(java.util.stream.Collectors.joining("\n"));
            }
            proc.waitFor();

            // Parse MAC from arp output
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("([0-9A-Fa-f]{2}[:\\-]){5}[0-9A-Fa-f]{2}")
                .matcher(output);
            if (m.find()) {
                return m.group(0);
            }
        } catch (Exception e) {
            log.debug("MAC resolution failed for IP {}: {}", clientIp, e.getMessage());
        }
        return "unknown";
    }

    private Map<String, Object> errorBody(String message) {
        return Map.of(
            "status", "error",
            "message", message,
            "timestamp", Instant.now().toString()
        );
    }
}
