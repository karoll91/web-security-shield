package uz.edu.security.websecurityshield.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import uz.edu.security.websecurityshield.security.RateLimitFilter;
import uz.edu.security.websecurityshield.security.SQLInjectionFilter;
import uz.edu.security.websecurityshield.security.XSSProtectionFilter;

/**
 * Spring Security konfiguratsiyasi - CSRF muammosi hal qilingan
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

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
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Authentication Provider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Security filter chain - CSRF to'g'ri sozlangan
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF - faqat H2 Console uchun o'chirish
                .csrf(csrf -> csrf
                                .ignoringRequestMatchers("/h2-console/**")
                        // Login sahifasi uchun CSRF yoqiq qoldirish
                )

                // URL autorizatsiyasi
                .authorizeHttpRequests(authz -> authz
                        // Public sahifalar
                        .requestMatchers("/", "/login", "/register").permitAll()
                        // Static fayllar
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                        // H2 Console
                        .requestMatchers("/h2-console/**").permitAll()
                        // Error pages
                        .requestMatchers("/error").permitAll()
                        // Actuator
                        .requestMatchers("/actuator/**").permitAll()
                        // Qolgan barcha sahifalar authentifikatsiya talab qiladi
                        .anyRequest().authenticated()
                )

                // Authentication Provider
                .authenticationProvider(authenticationProvider())

                // Form Login konfiguratsiyasi
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")  // POST /login ni Spring Security handle qiladi
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error=true")
                        .usernameParameter("username")  // HTML form field nomi
                        .passwordParameter("password")  // HTML form field nomi
                        .permitAll()
                )

                // Logout
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                // Session management
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )

                // Headers - H2 Console uchun frame options
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin()) // H2 Console uchun
                        .contentTypeOptions(contentTypeOptions -> {})
                        .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                        .addHeaderWriter(new StaticHeadersWriter("X-XSS-Protection", "1; mode=block"))
                );

        // Custom filterlar (ixtiyoriy)
        if (sqlInjectionFilter != null) {
            http.addFilterBefore(sqlInjectionFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (xssProtectionFilter != null) {
            http.addFilterAfter(xssProtectionFilter, SQLInjectionFilter.class);
        }

        if (rateLimitFilter != null) {
            http.addFilterBefore(rateLimitFilter, SQLInjectionFilter.class);
        }

        return http.build();
    }
}