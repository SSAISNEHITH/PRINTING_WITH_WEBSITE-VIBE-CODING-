package com.captiveportal.printserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Spring Security configuration for the Captive Portal Print Server.
 *
 * <p>Design rationale:
 * <ul>
 *   <li>The portal page itself is public — any connected hotspot client must reach it.</li>
 *   <li>The {@code /api/print} endpoint is public (no password) but hardened by the
 *       {@link com.captiveportal.printserver.security.FileValidationService} deep
 *       MIME-type check, size limit, and header inspection.</li>
 *   <li>The {@code /admin/**} path (status/logs) is protected by HTTP Basic auth.</li>
 *   <li>Aggressive security headers are applied globally to prevent MIME sniffing,
 *       framing, or information leakage.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ── Authorisation ──────────────────────────────────────────────
            .authorizeHttpRequests(auth -> auth
                // Public: portal UI + print API
                .requestMatchers(
                    "/",
                    "/portal",
                    "/generate_204",        // Android captive-portal detection
                    "/hotspot-detect.html", // Apple/iOS captive-portal detection
                    "/ncsi.txt",            // Windows Network Connectivity Status Indicator
                    "/connecttest.txt",     // Windows NCSI
                    "/redirect",            // Windows NCSI redirect
                    "/api/print",
                    "/css/**",
                    "/js/**",
                    "/img/**",
                    "/favicon.ico"
                ).permitAll()
                // Admin area requires BASIC auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // ── HTTP Basic for admin ────────────────────────────────────────
            .httpBasic(withDefaults())
            // ── Session management ─────────────────────────────────────────
            // Stateless for API calls; sessions only used for admin UI
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(5)
            )
            // ── CSRF: disabled for API endpoints, enabled for admin forms ──
            // The print endpoint is consumed from a direct HTML form POST with
            // no state we need to protect; CSRF would break the captive-portal flow
            // for clients that don't persist cookies.
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/print")
            )
            // ── Security headers ───────────────────────────────────────────
            .headers(headers -> headers
                .contentTypeOptions(withDefaults())
                .frameOptions(fo -> fo.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                )
                .referrerPolicy(rp ->
                    rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)
                )
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; "
                        + "script-src 'self' 'unsafe-inline'; "
                        + "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                        + "font-src 'self' https://fonts.gstatic.com; "
                        + "img-src 'self' data:; "
                        + "connect-src 'self'; "
                        + "form-action 'self'; "
                        + "frame-ancestors 'none';"
                    )
                )
                .addHeaderWriter((req, res) -> {
                    res.setHeader("X-Content-Type-Options", "nosniff");
                    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
                    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
                    res.setHeader("Pragma", "no-cache");
                    res.setHeader("Server", "PrintPortal");  // mask the real stack
                })
            );

        return http.build();
    }

    /**
     * Use the standard servlet multipart resolver (does NOT write temp files to disk
     * by default when threshold is not exceeded — controlled in application.yml).
     */
    @Bean
    public MultipartResolver multipartResolver() {
        return new StandardServletMultipartResolver();
    }
}
