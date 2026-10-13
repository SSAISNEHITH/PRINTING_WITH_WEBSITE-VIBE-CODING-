package com.captiveportal.printserver.config;

import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Configures the embedded Tomcat to redirect all 404s to the portal page.
 *
 * <p>This is essential for captive-portal operation: any URL a client tries to load
 * (e.g. www.google.com, apple.com/library/test/success.html) will 404 since this
 * server only serves /portal. Redirecting 404 → /portal ensures clients always land
 * on the upload page regardless of what URL their browser initially requested.
 */
@Component
public class WebServerConfig implements WebServerFactoryCustomizer<ConfigurableWebServerFactory> {

    @Override
    public void customize(ConfigurableWebServerFactory factory) {
        // Redirect HTTP 404 and 403 to the portal page
        factory.addErrorPages(
            new ErrorPage(HttpStatus.NOT_FOUND,  "/portal"),
            new ErrorPage(HttpStatus.FORBIDDEN,  "/portal"),
            new ErrorPage(HttpStatus.MOVED_PERMANENTLY, "/portal")
        );
    }
}
