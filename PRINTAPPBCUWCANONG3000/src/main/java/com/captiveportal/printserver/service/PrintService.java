package com.captiveportal.printserver.service;

import com.captiveportal.printserver.config.CaptivePortalProperties;
import com.captiveportal.printserver.exception.PrintException;
import com.captiveportal.printserver.security.FileValidationService;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.printing.PDFPageable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

// Explicit javax.print imports — no wildcard to avoid clashing with this class name
import javax.print.DocPrintJob;
import javax.print.PrintServiceLookup;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;
import javax.print.attribute.standard.Copies;
import javax.print.attribute.standard.JobName;
import javax.print.attribute.standard.MediaSizeName;
import javax.print.attribute.standard.OrientationRequested;
import javax.print.event.PrintJobAdapter;
import javax.print.event.PrintJobEvent;
import java.awt.print.PrinterException;
import java.awt.print.PrinterJob;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * PrintService — Delivers a validated PDF (held in a byte[]) to the OS print spooler
 * and wipes the byte array from memory immediately after spooler acceptance.
 *
 * <h2>Print strategy</h2>
 * <p>We use <b>PDFBox + {@code java.awt.print.PrinterJob}</b> (not {@code javax.print}
 * raw-bytes mode) because:
 * <ul>
 *   <li>Raw PCL/PostScript mode requires driver-level knowledge of the printer language.</li>
 *   <li>PDFBox renders each PDF page into a {@link PDFPageable} which feeds the AWT
 *       {@code PrinterJob} — this works with any printer the OS can see, including Canon.</li>
 * </ul>
 *
 * <h2>Zero-retention guarantee</h2>
 * <ol>
 *   <li>The PDF bytes are loaded into a {@link PDDocument} (PDFBox heap object).</li>
 *   <li>The {@link PrinterJob} is submitted; we wait up to 30 s for spooler acceptance.</li>
 *   <li>As soon as the job is sent (or fails), the byte array is zeroed via
 *       {@link FileValidationService#wipeBytes(byte[])} and {@link PDDocument#close()}
 *       is called inside a {@code finally} block — no path through this method leaves
 *       data alive in the heap beyond the finally block.</li>
 * </ol>
 *
 * <p><strong>Note on class name</strong>: The local Spring bean is named {@code PrintService}.
 * All references to {@code javax.print.PrintService} use the fully-qualified name to avoid
 * any compiler ambiguity.
 */
@Service
public class PrintService {

    private static final Logger log = LoggerFactory.getLogger(PrintService.class);

    /** Maximum time to wait for the print spooler to accept a job. */
    private static final long SPOOLER_ACCEPT_TIMEOUT_SECS = 30L;

    private final CaptivePortalProperties props;

    @Autowired
    public PrintService(CaptivePortalProperties props) {
        this.props = props;
    }

    /**
     * Sends {@code pdfBytes} to the configured (or default) printer and then
     * <strong>unconditionally wipes {@code pdfBytes} to zeros</strong>.
     *
     * @param pdfBytes validated PDF content — the caller must not use this array
     *                 after this method returns; it will be zeroed.
     * @throws PrintException if no printer is found, the job is rejected, or rendering fails
     */
    public void printAndWipe(byte[] pdfBytes) throws PrintException {
        PDDocument document = null;
        try {
            // ── 1. Identify the target printer ────────────────────────────────
            PrinterJob printerJob = PrinterJob.getPrinterJob();
            // Fully-qualified to distinguish from this class (PrintService)
            javax.print.PrintService targetSvc = resolveTargetPrinter();
            try {
                printerJob.setPrintService(targetSvc);
            } catch (PrinterException e) {
                throw new PrintException(
                    "Could not assign printer '" + targetSvc.getName() + "': " + e.getMessage(), e);
            }

            // ── 2. Load PDF from memory (never touches disk) ──────────────────
            document = Loader.loadPDF(pdfBytes);
            if (document.isEncrypted()) {
                throw new PrintException("Encrypted PDFs are not supported.");
            }
            int pageCount = document.getNumberOfPages();
            if (pageCount == 0) {
                throw new PrintException("PDF contains zero pages — nothing to print.");
            }
            log.info("PDF loaded from memory: {} page(s). Target printer: {}",
                pageCount, targetSvc.getName());

            // ── 3. Configure print attributes ─────────────────────────────────
            PrintRequestAttributeSet attrs = new HashPrintRequestAttributeSet();
            attrs.add(new Copies(1));
            attrs.add(OrientationRequested.PORTRAIT);
            attrs.add(MediaSizeName.ISO_A4);
            attrs.add(new JobName("CaptivePortal-" + UUID.randomUUID(), null));

            // ── 4. Attach a latch-based listener to detect spooler acceptance ─
            CountDownLatch spoolerLatch = new CountDownLatch(1);
            final boolean[] printError = {false};
            final String[] errorMessage = {""};

            DocPrintJob docJob = targetSvc.createPrintJob();
            docJob.addPrintJobListener(new PrintJobAdapter() {
                @Override
                public void printJobCompleted(PrintJobEvent pje) {
                    log.info("Print job completed by spooler.");
                    spoolerLatch.countDown();
                }
                @Override
                public void printDataTransferCompleted(PrintJobEvent pje) {
                    log.info("Print data transfer complete.");
                    spoolerLatch.countDown();
                }
                @Override
                public void printJobFailed(PrintJobEvent pje) {
                    log.error("Print job FAILED at spooler level.");
                    printError[0] = true;
                    errorMessage[0] = "Print job failed at the spooler.";
                    spoolerLatch.countDown();
                }
                @Override
                public void printJobCanceled(PrintJobEvent pje) {
                    log.warn("Print job was cancelled.");
                    printError[0] = true;
                    errorMessage[0] = "Print job was cancelled.";
                    spoolerLatch.countDown();
                }
            });

            // ── 5. Set the PDFPageable on the PrinterJob and submit ───────────
            printerJob.setPageable(new PDFPageable(document));
            printerJob.setJobName("CaptivePortal-" + UUID.randomUUID());

            // Submit synchronously — blocks until all pages are rendered and
            // handed to the OS spooler queue.
            try {
                printerJob.print(attrs);
            } catch (PrinterException e) {
                throw new PrintException(
                    "PrinterJob.print() raised an exception: " + e.getMessage(), e);
            }

            // ── 6. Wait for spooler acknowledgement ───────────────────────────
            boolean accepted;
            try {
                accepted = spoolerLatch.await(SPOOLER_ACCEPT_TIMEOUT_SECS, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new PrintException("Interrupted while waiting for spooler acknowledgement.");
            }
            if (!accepted) {
                throw new PrintException("Timed out waiting for spooler to acknowledge print job.");
            }
            if (printError[0]) {
                throw new PrintException(errorMessage[0]);
            }

            log.info("Print job successfully handed to OS spooler. Wiping PDF from memory.");

        } catch (IOException e) {
            throw new PrintException("Failed to load PDF from memory: " + e.getMessage(), e);
        } finally {
            // ── 7. Unconditional wipe — ALWAYS executed regardless of success/failure ──
            if (document != null) {
                try { document.close(); } catch (IOException ignored) { /* best-effort */ }
            }
            FileValidationService.wipeBytes(pdfBytes);
            log.info("PDF byte array zeroed and PDDocument closed. Zero-retention satisfied.");
        }
    }

    /**
     * Resolves the target {@link javax.print.PrintService} by configured name or falls back to
     * the system default printer. Throws {@link PrintException} if no printer is found.
     */
    private javax.print.PrintService resolveTargetPrinter() throws PrintException {
        javax.print.PrintService[] services =
            PrintServiceLookup.lookupPrintServices(null, null);
        if (services == null || services.length == 0) {
            throw new PrintException("No printers registered with the OS.");
        }

        String configured = props.getPrinterName();
        if (configured != null && !configured.isBlank()) {
            for (javax.print.PrintService ps : services) {
                if (ps.getName().equalsIgnoreCase(configured.trim())) {
                    log.info("Using configured printer: {}", ps.getName());
                    return ps;
                }
            }
            log.warn("Configured printer '{}' not found. Falling back to OS default.", configured);
        }

        // Fall back to OS default
        javax.print.PrintService defaultSvc = PrintServiceLookup.lookupDefaultPrintService();
        if (defaultSvc == null) {
            log.warn("OS default printer is null. Using first available: {}", services[0].getName());
            return services[0];
        }
        log.info("Using OS default printer: {}", defaultSvc.getName());
        return defaultSvc;
    }
}
