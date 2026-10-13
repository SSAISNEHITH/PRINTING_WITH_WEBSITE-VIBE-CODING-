package com.captiveportal.printserver.controller;

import com.captiveportal.printserver.config.CaptivePortalProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * PortalController — Serves the captive portal web UI and handles the OS-level
 * captive portal detection probes emitted by Android, iOS, and Windows.
 *
 * <h2>Captive portal detection responses</h2>
 * <ul>
 *   <li><b>Android</b>: GET {@code /generate_204} → we return HTTP 302 to the portal
 *       (Android accepts a 302 redirect as a captive-portal signal).</li>
 *   <li><b>Apple/iOS</b>: GET {@code /hotspot-detect.html} → 302 to portal.</li>
 *   <li><b>Windows NCSI</b>: GET {@code /ncsi.txt} and {@code /connecttest.txt} → 302
 *       to portal. Windows also checks for the literal string "Microsoft Connect Test"
 *       at /connecttest.txt — we redirect instead of serving it, forcing the NCSI
 *       captive-portal pop-up.</li>
 * </ul>
 *
 * <p>All redirects go to {@code /portal} which serves the upload form.
 */
@Controller
public class PortalController {

    private static final Logger log = LoggerFactory.getLogger(PortalController.class);

    private final CaptivePortalProperties props;

    @Autowired
    public PortalController(CaptivePortalProperties props) {
        this.props = props;
    }

    /** Root redirect → portal. */
    @GetMapping("/")
    public String root() {
        return "redirect:/portal";
    }

    /** Main captive portal page. */
    @GetMapping("/portal")
    public String portal(HttpServletRequest request, Model model) {
        log.info("Portal page served to IP={}", request.getRemoteAddr());
        model.addAttribute("maxSizeMb", props.getMaxPdfSizeBytes() / (1024 * 1024));
        return "portal";
    }

    /** Android captive portal probe → redirect. */
    @GetMapping("/generate_204")
    public String androidProbe() {
        return "redirect:/portal";
    }

    /** Apple/iOS captive portal probe → redirect. */
    @GetMapping("/hotspot-detect.html")
    public String appleProbe() {
        return "redirect:/portal";
    }

    /** Windows NCSI probe (connectivity check) → redirect to trigger captive-portal pop-up. */
    @GetMapping({"/ncsi.txt", "/connecttest.txt", "/redirect"})
    public String windowsNcsi() {
        return "redirect:/portal";
    }

    /** Favicon handler — return 204 to avoid 404 noise in logs. */
    @GetMapping("/favicon.ico")
    public void favicon(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.setStatus(204);
    }
}
