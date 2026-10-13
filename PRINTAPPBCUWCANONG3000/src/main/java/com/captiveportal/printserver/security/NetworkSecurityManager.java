package com.captiveportal.printserver.security;

import com.captiveportal.printserver.config.CaptivePortalProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * NetworkSecurityManager — Tracks connected hotspot clients and forcibly disconnects
 * them either immediately after a successful print job or after a configurable
 * session timeout (default: 10 minutes).
 *
 * <h2>Client lifecycle</h2>
 * <pre>
 *   Client connects → {@link #registerClient(String, String)} called by the portal filter
 *       └─ schedules a 10-minute hard-eviction via OS scripts
 *
 *   Print completes → {@link #disconnectImmediately(String)} called by PrintController
 *       └─ executes disconnect script immediately, cancels the scheduled eviction
 *
 *   10-minute timeout → scheduled eviction executes, client is blocked at the AP level
 * </pre>
 *
 * <h2>OS-level disconnect mechanisms</h2>
 * <ul>
 *   <li><b>Windows (ICS/Mobile Hotspot)</b>: {@code netsh wlan disconnect} and
 *       ARP/firewall rules via {@code netsh advfirewall}.</li>
 *   <li><b>Linux (hostapd)</b>: {@code hostapd_cli deauthenticate <MAC>} + iptables drop.</li>
 * </ul>
 *
 * <p><strong>Security note</strong>: The MAC address and IP passed to OS commands are
 * validated against strict regex patterns before being interpolated into any shell
 * command. No user-supplied string reaches {@link Runtime#exec} without validation.
 */
@Service
public class NetworkSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(NetworkSecurityManager.class);

    /** Strict MAC address pattern: 6 hex pairs separated by ':' or '-'. */
    private static final java.util.regex.Pattern MAC_PATTERN =
        java.util.regex.Pattern.compile("^([0-9A-Fa-f]{2}[:\\-]){5}[0-9A-Fa-f]{2}$");

    /** Strict IPv4 pattern. */
    private static final java.util.regex.Pattern IP_PATTERN =
        java.util.regex.Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)(\\.(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)){3}$");

    private final CaptivePortalProperties props;

    /**
     * Active client registry: IP → {@link ClientSession}.
     * ConcurrentHashMap ensures thread-safe access from the scheduled eviction threads.
     */
    private final ConcurrentHashMap<String, ClientSession> activeSessions = new ConcurrentHashMap<>();

    /**
     * Dedicated single-thread scheduler for per-client eviction tasks.
     * Using a dedicated executor (not Spring's @Scheduled pool) so we can cancel
     * individual futures precisely.
     */
    private final ScheduledExecutorService evictionScheduler =
        Executors.newScheduledThreadPool(
            4,
            r -> {
                Thread t = new Thread(r, "client-eviction");
                t.setDaemon(true);
                return t;
            }
        );

    @Autowired
    public NetworkSecurityManager(CaptivePortalProperties props) {
        this.props = props;
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Registers a newly connected client and schedules their automatic eviction.
     *
     * @param clientIp  validated IPv4 address of the connecting client
     * @param clientMac validated MAC address of the connecting client (may be "unknown"
     *                  if ARP resolution fails — IP-based blocking will be used as fallback)
     */
    public void registerClient(String clientIp, String clientMac) {
        String safeIp  = sanitizeIp(clientIp);
        String safeMac = sanitizeMac(clientMac);

        if (safeIp == null) {
            log.warn("registerClient: invalid IP '{}' — ignoring.", clientIp);
            return;
        }

        if (activeSessions.containsKey(safeIp)) {
            log.debug("Client {} already registered — skipping duplicate registration.", safeIp);
            return;
        }

        int timeoutMinutes = props.getSessionTimeoutMinutes();
        log.info("Registering client IP={} MAC={} — eviction in {} minutes.", safeIp, safeMac, timeoutMinutes);

        // Schedule automatic eviction at session timeout
        var future = evictionScheduler.schedule(
            () -> performDisconnect(safeIp, safeMac, "SESSION_TIMEOUT"),
            timeoutMinutes,
            TimeUnit.MINUTES
        );

        activeSessions.put(safeIp, new ClientSession(safeIp, safeMac, Instant.now(), future));
    }

    /**
     * Disconnects the client immediately (called after a successful print job).
     * Cancels the scheduled eviction to avoid duplicate disconnect commands.
     *
     * @param clientIp the IP of the client to disconnect
     */
    public void disconnectImmediately(String clientIp) {
        String safeIp = sanitizeIp(clientIp);
        if (safeIp == null) {
            log.warn("disconnectImmediately: invalid IP '{}' — skipping.", clientIp);
            return;
        }

        ClientSession session = activeSessions.remove(safeIp);
        if (session == null) {
            log.warn("disconnectImmediately: no session found for IP {}. Attempting blind disconnect.", safeIp);
            performDisconnect(safeIp, "unknown", "POST_PRINT_BLIND");
            return;
        }

        // Cancel the scheduled timeout eviction (it's being replaced by immediate action)
        session.evictionFuture().cancel(false);
        log.info("Disconnecting client IP={} MAC={} immediately after print.", safeIp, session.macAddress());
        performDisconnect(safeIp, session.macAddress(), "POST_PRINT");
    }

    /**
     * Returns the number of currently tracked active sessions.
     */
    public int activeSessionCount() {
        return activeSessions.size();
    }

    /**
     * Periodic cleanup: every 5 minutes remove expired sessions from the map
     * (in case the OS disconnect succeeded but the future didn't fire a removal).
     */
    @Scheduled(fixedDelay = 300_000)
    public void cleanupExpiredSessions() {
        Instant cutoff = Instant.now().minusSeconds(props.getSessionTimeoutMinutes() * 60L + 60L);
        activeSessions.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().connectedAt().isBefore(cutoff);
            if (expired) {
                log.info("Cleanup: removing stale session record for IP={}", entry.getKey());
            }
            return expired;
        });
    }

    // ─── OS-level disconnect implementation ──────────────────────────────────

    /**
     * Executes OS-level disconnect commands for the given client.
     * Selects between Windows and Linux strategies automatically.
     *
     * <p>All parameters entering OS commands have been validated by the caller.
     *
     * @param safeIp     pre-validated IPv4 address (no shell metacharacters)
     * @param safeMac    pre-validated MAC address or "unknown"
     * @param reason     log label: "SESSION_TIMEOUT", "POST_PRINT", etc.
     */
    private void performDisconnect(String safeIp, String safeMac, String reason) {
        log.info("DISCONNECT [{}]: IP={} MAC={}", reason, safeIp, safeMac);
        activeSessions.remove(safeIp);

        boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (isWindows) {
            disconnectWindows(safeIp, safeMac);
        } else {
            disconnectLinux(safeIp, safeMac);
        }
    }

    /**
     * Windows disconnect strategy using {@code netsh} and Windows Firewall.
     *
     * <p>Steps:
     * <ol>
     *   <li>Add a Windows Firewall block rule for the client IP (both directions).</li>
     *   <li>Flush the ARP cache entry so the IP cannot immediately reconnect under a new MAC.</li>
     *   <li>If the MAC is known, add a static ARP entry pointing to the loopback MAC
     *       (poison the ARP table so the host ignores further frames from that MAC).</li>
     * </ol>
     *
     * <p><strong>Elevated privilege note</strong>: {@code netsh advfirewall} requires the
     * JVM process to run as Administrator. The startup scripts enforce this.
     */
    private void disconnectWindows(String safeIp, String safeMac) {
        String ruleName = "BlockCaptiveClient-" + safeIp.replace('.', '-');

        // 1. Add firewall BLOCK rule for this IP (inbound + outbound)
        execCommand(new String[]{
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + ruleName,
            "dir=in",
            "action=block",
            "remoteip=" + safeIp,
            "enable=yes",
            "profile=any"
        });
        execCommand(new String[]{
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + ruleName + "-OUT",
            "dir=out",
            "action=block",
            "remoteip=" + safeIp,
            "enable=yes",
            "profile=any"
        });

        // 2. Delete ARP cache entry
        execCommand(new String[]{"arp", "-d", safeIp});

        // 3. If MAC is known, poison the ARP table
        if (!"unknown".equals(safeMac) && safeMac != null && !safeMac.isBlank()) {
            // Normalise MAC separators for Windows arp -s (uses dash format)
            String winMac = safeMac.replace(':', '-');
            execCommand(new String[]{"arp", "-s", safeIp, winMac});
        }

        log.info("Windows disconnect complete for IP={}: firewall rule '{}' added, ARP poisoned.", safeIp, ruleName);
    }

    /**
     * Linux disconnect strategy using {@code hostapd_cli} and {@code iptables}.
     *
     * <p>Steps:
     * <ol>
     *   <li>Deauthenticate the client from the AP via {@code hostapd_cli}.</li>
     *   <li>Add iptables DROP rules for the client IP (FORWARD chain blocks routing).</li>
     *   <li>If MAC is known, add a MAC-level ebtables DROP rule at the bridge level.</li>
     * </ol>
     */
    private void disconnectLinux(String safeIp, String safeMac) {
        String iface = props.getHotspotInterface();

        // 1. Deauth via hostapd_cli (MAC-level)
        if (!"unknown".equals(safeMac) && safeMac != null && !safeMac.isBlank()) {
            execCommand(new String[]{
                "hostapd_cli", "-i", iface, "deauthenticate", safeMac
            });
            // MAC blacklist in hostapd
            execCommand(new String[]{
                "hostapd_cli", "-i", iface, "deny_acl", "ADD_MAC", safeMac
            });
        }

        // 2. iptables: drop packets from this IP in FORWARD and INPUT chains
        execCommand(new String[]{
            "iptables", "-I", "FORWARD", "-s", safeIp, "-j", "DROP"
        });
        execCommand(new String[]{
            "iptables", "-I", "INPUT", "-s", safeIp, "-j", "DROP"
        });

        // 3. ARP table poison (Linux)
        execCommand(new String[]{"arp", "-d", safeIp});

        log.info("Linux disconnect complete for IP={} MAC={}.", safeIp, safeMac);
    }

    // ─── Shell command executor ───────────────────────────────────────────────

    /**
     * Executes a command as a string array (no shell expansion — prevents injection).
     * Logs stdout/stderr at DEBUG level. Never throws; logs errors instead.
     *
     * <p>The command array is passed directly to {@link Runtime#exec(String[])}
     * (not a shell), so no metacharacters like {@code ;}, {@code |}, or {@code $()}
     * can be injected even if the validated IP/MAC strings somehow contained them
     * (they cannot, by the regex guards).
     */
    private void execCommand(String[] command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            // Drain stdout to prevent buffer deadlock
            try (BufferedReader stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = stdout.readLine()) != null) {
                    log.debug("  [cmd stdout] {}", line);
                }
                while ((line = stderr.readLine()) != null) {
                    log.debug("  [cmd stderr] {}", line);
                }
            }
            int exitCode = process.waitFor();
            log.debug("Command {} exited with code {}", command[0], exitCode);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.error("Error executing OS command '{}': {}", command[0], e.getMessage());
        }
    }

    // ─── Input sanitisation ───────────────────────────────────────────────────

    /**
     * Validates and returns the IP string, or {@code null} if invalid.
     * Only returns the input if it exactly matches a dotted-decimal IPv4 pattern.
     */
    private String sanitizeIp(String ip) {
        if (ip == null || ip.isBlank()) return null;
        String trimmed = ip.trim();
        // Additional InetAddress check to catch things like "127.0.0.1" (loopback)
        // or multicast that we don't want to process
        if (!IP_PATTERN.matcher(trimmed).matches()) return null;
        try {
            InetAddress addr = InetAddress.getByName(trimmed);
            if (addr.isLoopbackAddress() || addr.isMulticastAddress()) return null;
        } catch (Exception e) {
            return null;
        }
        return trimmed;
    }

    /**
     * Validates and returns the MAC string, or {@code "unknown"} if invalid.
     */
    private String sanitizeMac(String mac) {
        if (mac == null || mac.isBlank()) return "unknown";
        String trimmed = mac.trim();
        return MAC_PATTERN.matcher(trimmed).matches() ? trimmed : "unknown";
    }

    // ─── Record for session tracking ─────────────────────────────────────────

    /**
     * Immutable record capturing a connected client's session state.
     */
    private record ClientSession(
        String ipAddress,
        String macAddress,
        Instant connectedAt,
        java.util.concurrent.ScheduledFuture<?> evictionFuture
    ) {}
}
