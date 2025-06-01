package uz.edu.security.websecurityshield.security;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.service.SecurityService;

import java.io.IOException;
import java.util.Enumeration;

/**
 * XSS (Cross-Site Scripting) hujumlaridan himoya qiluvchi filter
 */
@Component
public class XSSProtectionFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(XSSProtectionFilter.class);

    @Autowired
    private SecurityService securityService;

    @Value("${security.xss-protection.enabled:true}")
    private boolean xssProtectionEnabled;

    @Value("${security.xss-protection.block-mode:true}")
    private boolean blockMode;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("XSS Protection Filter ishga tushdi. Enabled: {}, Block Mode: {}",
                xssProtectionEnabled, blockMode);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        if (!xssProtectionEnabled) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String ipAddress = getClientIpAddress(request);
        String requestUrl = request.getRequestURL().toString();
        String method = request.getMethod();

        // XSS hujumini tekshirish
        boolean xssDetected = checkForXSS(request);

        if (xssDetected) {
            logger.warn("XSS hujumi aniqlandi! IP: {}, URL: {}, Method: {}",
                    ipAddress, requestUrl, method);

            // Hujumni qayta ishlash
            boolean blocked = securityService.handleSecurityThreat(
                    SecurityLog.ThreatType.XSS_ATTACK,
                    ipAddress,
                    requestUrl,
                    getAttackPayload(request)
            );

            if (blocked && blockMode) {
                // Hujumni bloklash
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"XSS hujumi aniqlandi va bloklandi\",\"code\":\"XSS_BLOCKED\"}");
                return;
            }
        }

        // Agar hujum yo'q yoki block mode o'chiq bo'lsa, davom etish
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * XSS hujumini tekshirish
     */
    private boolean checkForXSS(HttpServletRequest request) {
        // 1. URL parametrlarini tekshirish
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String[] paramValues = request.getParameterValues(paramName);

            if (paramValues != null) {
                for (String paramValue : paramValues) {
                    if (securityService.detectXSS(paramValue)) {
                        return true;
                    }
                }
            }
        }

        // 2. Header larni tekshirish
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);

            if (securityService.detectXSS(headerValue)) {
                return true;
            }
        }

        // 3. User-Agent ni tekshirish
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && securityService.detectXSS(userAgent)) {
            return true;
        }

        // 4. Referer ni tekshirish
        String referer = request.getHeader("Referer");
        if (referer != null && securityService.detectXSS(referer)) {
            return true;
        }

        return false;
    }

    /**
     * Hujum payload ini olish
     */
    private String getAttackPayload(HttpServletRequest request) {
        StringBuilder payload = new StringBuilder();

        // Parametrlardan payload qidirish
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String[] paramValues = request.getParameterValues(paramName);

            if (paramValues != null) {
                for (String paramValue : paramValues) {
                    if (securityService.detectXSS(paramValue)) {
                        payload.append(paramName).append("=").append(paramValue).append("; ");
                    }
                }
            }
        }

        // Header lardan payload qidirish
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);

            if (headerValue != null && securityService.detectXSS(headerValue)) {
                payload.append(headerName).append(": ").append(headerValue).append("; ");
            }
        }

        return payload.length() > 0 ? payload.toString() : "XSS payload detected";
    }

    /**
     * Client IP manzilini olish
     */
    private String getClientIpAddress(HttpServletRequest request) {
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

    @Override
    public void destroy() {
        logger.info("XSS Protection Filter to'xtatildi");
    }
}
