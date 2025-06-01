package uz.edu.security.websecurityshield.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import uz.edu.security.websecurityshield.security.RateLimitFilter;
import uz.edu.security.websecurityshield.security.SQLInjectionFilter;
import uz.edu.security.websecurityshield.security.XSSProtectionFilter;

/**
 * Spring Security konfiguratsiyasi (Spring Security 6.1+ compatible)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired(required = false)
    private XSSProtectionFilter xssProtectionFilter;

    @Autowired(required = false)
    private SQLInjectionFilter sqlInjectionFilter;

    @Autowired(required = false)
    private RateLimitFilter rateLimitFilter;

    /**
     * Password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Yuqori xavfsizlik uchun 12 rounds
    }

    /**
     * Security filter chain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF himoyasi
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**", "/api/**")
                )

                // URL autorizatsiyasi
                .authorizeHttpRequests(authz -> authz
                        // H2 Console - to'liq access
                        .requestMatchers("/h2-console/**").permitAll()
                        // Umumiy sahifalar
                        .requestMatchers("/", "/login", "/register").permitAll()
                        // Static fayllar
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                        // API endpoints (agar kerak bo'lsa)
                        .requestMatchers("/api/public/**").permitAll()
                        // Error pages
                        .requestMatchers("/error").permitAll()
                        // Actuator endpoints
                        .requestMatchers("/actuator/**").permitAll()
                        // Qolgan barcha sahifalar authentifikatsiya talab qiladi
                        .anyRequest().authenticated()
                )

                // Login konfiguratsiyasi
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )

                // Logout konfiguratsiyasi
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                // Session management
                .sessionManagement(session -> session
                        .maximumSessions(1) // Bir vaqtda faqat bitta session
                        .maxSessionsPreventsLogin(false) // Yangi login eskisini o'chiradi
                )

                // Security headers - to'liq yangilangan
                .headers(headers -> headers
                        // Content Type Options
                        .contentTypeOptions(contentTypeOptions -> {})

                        // Frame Options - H2 Console uchun exception
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())

                        // Referrer Policy - yangi usul
                        .addHeaderWriter(new StaticHeadersWriter("Referrer-Policy", "strict-origin-when-cross-origin"))

                        // HTTP Strict Transport Security - yangi usul
                        .addHeaderWriter(new StaticHeadersWriter("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains; preload"))

                        // Qolgan security headers
                        .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                        .addHeaderWriter(new StaticHeadersWriter("X-XSS-Protection", "1; mode=block"))
                        .addHeaderWriter(new StaticHeadersWriter("X-Permitted-Cross-Domain-Policies", "none"))
                        .addHeaderWriter(new StaticHeadersWriter("X-Download-Options", "noopen"))

                        // Content Security Policy - H2 Console uchun relaxed
                        .addHeaderWriter(new StaticHeadersWriter("Content-Security-Policy",
                                "default-src 'self'; " +
                                        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
                                        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
                                        "img-src 'self' data: https:; " +
                                        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
                                        "connect-src 'self'; " +
                                        "frame-src 'self'; " +
                                        "base-uri 'self'; " +
                                        "form-action 'self'"))

                        // Permissions Policy (yangi Feature Policy)
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
                );

        // Custom filterlarni conditional qo'shish
        if (rateLimitFilter != null) {
            http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (xssProtectionFilter != null) {
            http.addFilterBefore(xssProtectionFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (sqlInjectionFilter != null) {
            http.addFilterBefore(sqlInjectionFilter, UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }
}