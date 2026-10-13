package com.captiveportal.printserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Strongly-typed binding of the {@code captive-portal.*} namespace in application.yml.
 */
@ConfigurationProperties(prefix = "captive-portal")
public class CaptivePortalProperties {

    /** Maximum allowed PDF upload size in bytes. Default: 10 MB. */
    private long maxPdfSizeBytes = 10_485_760L;

    /** Minutes until a connected client is forcibly disconnected. Default: 10. */
    private int sessionTimeoutMinutes = 10;

    /** Exact printer name as registered in the OS. Empty = OS default. */
    private String printerName = "";

    /** Network interface name for the hotspot (e.g. "Wi-Fi 2" on Windows, "wlan0" on Linux). */
    private String hotspotInterface = "Wi-Fi 2";

    /** This machine's IP address on the hotspot network. */
    private String portalIp = "192.168.137.1";

    /** Directory where OS-level helper scripts reside. */
    private String scriptsDir = "scripts";

    /** Optional override for temporary file directory. Empty = system temp. */
    private String tempDir = "";

    // ─── Getters & Setters ────────────────────────────────────────────────────

    public long getMaxPdfSizeBytes() { return maxPdfSizeBytes; }
    public void setMaxPdfSizeBytes(long maxPdfSizeBytes) { this.maxPdfSizeBytes = maxPdfSizeBytes; }

    public int getSessionTimeoutMinutes() { return sessionTimeoutMinutes; }
    public void setSessionTimeoutMinutes(int sessionTimeoutMinutes) { this.sessionTimeoutMinutes = sessionTimeoutMinutes; }

    public String getPrinterName() { return printerName; }
    public void setPrinterName(String printerName) { this.printerName = printerName; }

    public String getHotspotInterface() { return hotspotInterface; }
    public void setHotspotInterface(String hotspotInterface) { this.hotspotInterface = hotspotInterface; }

    public String getPortalIp() { return portalIp; }
    public void setPortalIp(String portalIp) { this.portalIp = portalIp; }

    public String getScriptsDir() { return scriptsDir; }
    public void setScriptsDir(String scriptsDir) { this.scriptsDir = scriptsDir; }

    public String getTempDir() { return tempDir; }
    public void setTempDir(String tempDir) { this.tempDir = tempDir; }
}
