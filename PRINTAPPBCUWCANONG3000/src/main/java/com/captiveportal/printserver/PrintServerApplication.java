package com.captiveportal.printserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the Captive Portal Print Server.
 *
 * <p>This application:
 * <ol>
 *   <li>Serves a captive-portal page to every Wi-Fi client on the hotspot</li>
 *   <li>Accepts a single PDF, validates it deeply, prints it immediately</li>
 *   <li>Hard-deletes the PDF from memory immediately after the print job is accepted</li>
 *   <li>Disconnects the client from the hotspot after print (or after 10-minute timeout)</li>
 * </ol>
 */
@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(com.captiveportal.printserver.config.CaptivePortalProperties.class)
public class PrintServerApplication {

    public static void main(String[] args) {
        // Disable Headless mode so javax.print can access print services
        System.setProperty("java.awt.headless", "false");
        SpringApplication.run(PrintServerApplication.class, args);
    }
}
