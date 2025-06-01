package uz.edu.security.websecurityshield.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.*;

/**
 * Web konfiguratsiyasi
 */
@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    /**
     * Static resurslar uchun handler
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // CSS fayllar
        registry.addResourceHandler("/css/**")
                .addResourceLocations("classpath:/static/css/")
                .setCachePeriod(3600); // 1 soat cache

        // JavaScript fayllar
        registry.addResourceHandler("/js/**")
                .addResourceLocations("classpath:/static/js/")
                .setCachePeriod(3600);

        // Rasmlar
        registry.addResourceHandler("/images/**")
                .addResourceLocations("classpath:/static/images/")
                .setCachePeriod(86400); // 1 kun cache

        // Favicon
        registry.addResourceHandler("/favicon.ico")
                .addResourceLocations("classpath:/static/")
                .setCachePeriod(86400);
    }

    /**
     * View Controller lar
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Bosh sahifa
        registry.addViewController("/").setViewName("redirect:/dashboard");

        // Error sahifalar
        registry.addViewController("/403").setViewName("error/403");
        registry.addViewController("/404").setViewName("error/404");
        registry.addViewController("/500").setViewName("error/500");
    }

    /**
     * CORS konfiguratsiyasi (agar API kerak bo'lsa)
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:8080")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }

    /**
     * Interceptor lar
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Security logging interceptor
        registry.addInterceptor(new SecurityLoggingInterceptor())
                .addPathPatterns("/**")
                .excludePathPatterns("/css/**", "/js/**", "/images/**", "/favicon.ico");
    }

    /**
     * Security Logging Interceptor
     */
    public static class SecurityLoggingInterceptor implements HandlerInterceptor {

        @Override
        public boolean preHandle(jakarta.servlet.http.HttpServletRequest request,
                                 jakarta.servlet.http.HttpServletResponse response,
                                 Object handler) throws Exception {

            // Request ma'lumotlarini log qilish
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");
            String requestUrl = request.getRequestURL().toString();
            String method = request.getMethod();

            // Shubhali User-Agent larni tekshirish
            if (userAgent != null && isSuspiciousUserAgent(userAgent)) {
                // Shubhali request deb belgilash
                request.setAttribute("suspicious", true);
            }

            return true;
        }

        private String getClientIpAddress(jakarta.servlet.http.HttpServletRequest request) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }

            return request.getRemoteAddr();
        }

        private boolean isSuspiciousUserAgent(String userAgent) {
            String lowerUserAgent = userAgent.toLowerCase();

            // Ma'lum bot va scanner lar
            String[] suspiciousAgents = {
                    "sqlmap", "nikto", "nmap", "masscan", "zap",
                    "burp", "w3af", "acunetix", "nessus", "openvas",
                    "curl", "wget", "python-requests", "php",
                    "scanner", "exploit", "attack", "hack"
            };

            for (String suspicious : suspiciousAgents) {
                if (lowerUserAgent.contains(suspicious)) {
                    return true;
                }
            }

            return false;
        }
    }
}