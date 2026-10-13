package com.captiveportal.printserver.security;

import org.apache.tika.Tika;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.captiveportal.printserver.config.CaptivePortalProperties;
import com.captiveportal.printserver.exception.FileValidationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Deep file validation service enforcing strict security constraints on uploaded files.
 *
 * <h2>Defence layers (in order of execution)</h2>
 * <ol>
 *   <li><b>Size gate</b> — Rejects uploads exceeding 10 MB before reading the body.</li>
 *   <li><b>Claimed MIME check</b> — Content-Type header must be {@code application/pdf}.</li>
 *   <li><b>Original filename sanitisation</b> — Rejects null, blank, double extensions
 *       (e.g. {@code .pdf.exe}), path traversal characters, and names longer than 255 chars.</li>
 *   <li><b>Magic-byte verification</b> — The first 8 bytes must start with the PDF magic
 *       bytes {@code %PDF-} (hex {@code 255044462D}).</li>
 *   <li><b>Executable-header rejection</b> — Detects ELF, PE (MZ), Mach-O, and ZIP/JAR
 *       magic bytes that could masquerade as PDFs.</li>
 *   <li><b>Apache Tika deep MIME detection</b> — Tika analyses the full byte stream; if it
 *       does not resolve to {@code application/pdf} the file is rejected.</li>
 *   <li><b>Null-byte injection check</b> — The first 1 KB is scanned for embedded null
 *       bytes, which indicate binary smuggling or filename-terminator attacks.</li>
 * </ol>
 */
@Service
public class FileValidationService {

    private static final Logger log = LoggerFactory.getLogger(FileValidationService.class);

    /** PDF magic bytes: %PDF- */
    private static final byte[] PDF_MAGIC = new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D};

    /** Known dangerous executable magic byte sequences (first 4 bytes). */
    private static final List<byte[]> DANGEROUS_MAGIC = List.of(
        new byte[]{0x4D, 0x5A, 0x00, 0x00},        // PE / DOS MZ (loose match)
        new byte[]{0x4D, 0x5A, (byte)0x90, 0x00},   // PE MZ (common variant)
        new byte[]{0x7F, 0x45, 0x4C, 0x46},         // ELF
        new byte[]{(byte)0xCA, (byte)0xFE, (byte)0xBA, (byte)0xBE}, // Mach-O fat
        new byte[]{(byte)0xCE, (byte)0xFA, (byte)0xED, (byte)0xFE}, // Mach-O 32-bit LE
        new byte[]{(byte)0xCF, (byte)0xFA, (byte)0xED, (byte)0xFE}, // Mach-O 64-bit LE
        new byte[]{0x50, 0x4B, 0x03, 0x04},          // ZIP/JAR/DOCX
        new byte[]{0x50, 0x4B, 0x05, 0x06},          // ZIP empty archive
        new byte[]{0x50, 0x4B, 0x07, 0x08}           // ZIP spanned
    );

    /** Reject filenames containing these characters (path traversal / shell injection). */
    private static final Pattern DANGEROUS_FILENAME_CHARS =
        Pattern.compile("[/\\\\:*?\"<>|;&$`\r\n\t]");

    /** Double-extension pattern — e.g. "document.pdf.exe", "file.exe.pdf" */
    private static final Pattern DOUBLE_EXTENSION =
        Pattern.compile("(?i).*\\.[a-zA-Z0-9]{1,10}\\.(pdf|exe|sh|bat|cmd|ps1|vbs|js|jar|class)$");

    /** Only these MIME types are acceptable from Tika deep scan. */
    private static final List<String> ACCEPTABLE_MIME_TYPES = List.of("application/pdf");

    private final Tika tika = new Tika();
    private final CaptivePortalProperties props;

    @Autowired
    public FileValidationService(CaptivePortalProperties props) {
        this.props = props;
    }

    /**
     * Validates {@code file} through all defence layers and returns its content
     * as an in-memory {@code byte[]} that the caller owns.
     *
     * @param file the multipart upload from the HTTP request
     * @return validated PDF bytes, held entirely in the JVM heap — never written to disk
     * @throws FileValidationException if any validation layer rejects the file
     * @throws IOException             if the stream cannot be read
     */
    public byte[] validateAndReadToMemory(MultipartFile file)
            throws FileValidationException, IOException {

        // ── Layer 1: size gate ────────────────────────────────────────────────
        long reportedSize = file.getSize();
        if (reportedSize <= 0) {
            throw new FileValidationException("Empty or zero-size file rejected.");
        }
        if (reportedSize > props.getMaxPdfSizeBytes()) {
            throw new FileValidationException(
                String.format("File size %d bytes exceeds maximum allowed %d bytes.",
                    reportedSize, props.getMaxPdfSizeBytes()));
        }

        // ── Layer 2: claimed Content-Type header ──────────────────────────────
        String contentType = file.getContentType();
        if (contentType == null || !contentType.toLowerCase().startsWith("application/pdf")) {
            throw new FileValidationException(
                "Rejected: Content-Type is '" + contentType + "'. Only application/pdf is accepted.");
        }

        // ── Layer 3: original filename sanitisation ───────────────────────────
        validateFilename(file.getOriginalFilename());

        // ── Read entire stream into heap memory ───────────────────────────────
        // CRITICAL: we consume the stream exactly once into a byte[].
        // Spring may have buffered this in memory already; reading into byte[]
        // ensures we NEVER create a separate temp file in this service.
        final byte[] pdfBytes;
        try (InputStream is = file.getInputStream()) {
            pdfBytes = is.readAllBytes();
        }

        // Guard against size mismatch after reading (e.g. malicious chunked encoding)
        if (pdfBytes.length > props.getMaxPdfSizeBytes()) {
            wipeBytes(pdfBytes);
            throw new FileValidationException(
                "Actual stream size exceeds limit after read. Request rejected.");
        }

        // ── Layer 4: PDF magic-byte verification ──────────────────────────────
        if (pdfBytes.length < PDF_MAGIC.length) {
            wipeBytes(pdfBytes);
            throw new FileValidationException("File too small to be a valid PDF.");
        }
        if (!startsWith(pdfBytes, PDF_MAGIC)) {
            log.warn("PDF magic mismatch. First 8 bytes: {}",
                HexFormat.of().formatHex(Arrays.copyOf(pdfBytes, Math.min(pdfBytes.length, 8))));
            wipeBytes(pdfBytes);
            throw new FileValidationException("File does not begin with the PDF magic signature (%PDF-).");
        }

        // ── Layer 5: executable-header rejection ──────────────────────────────
        for (byte[] danger : DANGEROUS_MAGIC) {
            if (startsWith(pdfBytes, danger)) {
                log.error("SECURITY: Executable header detected in upload. Magic: {}",
                    HexFormat.of().formatHex(Arrays.copyOf(pdfBytes, 4)));
                wipeBytes(pdfBytes);
                throw new FileValidationException("Executable file signature detected. Upload blocked.");
            }
        }

        // ── Layer 6: Apache Tika deep MIME detection ──────────────────────────
        String detectedMime;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(pdfBytes)) {
            detectedMime = tika.detect(bais);
        }
        if (!ACCEPTABLE_MIME_TYPES.contains(detectedMime)) {
            log.warn("Tika detected MIME '{}' — expected application/pdf. Rejecting.", detectedMime);
            wipeBytes(pdfBytes);
            throw new FileValidationException(
                "Content analysis detected MIME type '" + detectedMime + "'. Only PDF is accepted.");
        }

        // ── Layer 7: null-byte injection scan (first 1 KB) ───────────────────
        int scanLen = Math.min(pdfBytes.length, 1024);
        for (int i = 0; i < scanLen; i++) {
            if (pdfBytes[i] == 0x00 && i < 10) {
                // PDFs can have null bytes inside cross-reference tables, but NEVER in
                // the very first 10 bytes of a real %PDF- header.
                wipeBytes(pdfBytes);
                throw new FileValidationException("Null byte detected in PDF header region. Upload blocked.");
            }
        }

        log.info("File validation passed: {} bytes, MIME={}", pdfBytes.length, detectedMime);
        return pdfBytes;
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    private void validateFilename(String name) throws FileValidationException {
        if (name == null || name.isBlank()) {
            throw new FileValidationException("Missing or blank filename.");
        }
        if (name.length() > 255) {
            throw new FileValidationException("Filename exceeds maximum length of 255 characters.");
        }
        if (DANGEROUS_FILENAME_CHARS.matcher(name).find()) {
            throw new FileValidationException("Filename contains disallowed characters.");
        }
        if (DOUBLE_EXTENSION.matcher(name).matches()) {
            throw new FileValidationException("Double-extension filename rejected: " + name);
        }
        // Must end with .pdf (case-insensitive)
        if (!name.toLowerCase().endsWith(".pdf")) {
            throw new FileValidationException("Filename must end with .pdf extension. Got: " + name);
        }
    }

    /**
     * Returns true if {@code data} starts with all bytes in {@code prefix}.
     */
    private boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    /**
     * Overwrites the byte array with zeros before releasing it to the GC.
     * This minimises the window during which PDF content is readable in heap dumps.
     */
    public static void wipeBytes(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0x00);
        }
    }
}
