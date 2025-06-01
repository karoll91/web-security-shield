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
 * SQL Injection hujumlaridan himoya qiluvchi filter
 */
@Component
public class SQLInjectionFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(SQLInjectionFilter.class);

    @Autowired
    private SecurityService securityService;

    @Value("${security.sql-injection.enabled:true}")
    private boolean sqlInjectionProtectionEnabled;

    @Value("${security.sql-injection.strict-mode:false}")
    private boolean strictMode;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("SQL Injection Protection Filter ishga tushdi. Enabled: {}, Strict Mode: {}",
                sqlInjectionProtectionEnabled, strictMode);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        if (!sqlInjectionProtectionEnabled) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String ipAddress = getClientIpAddress(request);
        String requestUrl = request.getRequestURL().toString();
        String method = request.getMethod();

        // SQL Injection hujumini tekshirish
        boolean sqlInjectionDetected = checkForSQLInjection(request);

        if (sqlInjectionDetected) {
            logger.warn("SQL Injection hujumi aniqlandi! IP: {}, URL: {}, Method: {}",
                    ipAddress, requestUrl, method);

            // Hujumni qayta ishlash
            boolean blocked = securityService.handleSecurityThreat(
                    SecurityLog.ThreatType.SQL_INJECTION,
                    ipAddress,
                    requestUrl,
                    getAttackPayload(request)
            );

            if (blocked) {
                // Hujumni bloklash
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"SQL Injection hujumi aniqlandi va bloklandi\",\"code\":\"SQL_INJECTION_BLOCKED\"}");
                return;
            }
        }

        // Agar hujum yo'q yoki block qilinmagan bo'lsa, davom etish
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * SQL Injection hujumini tekshirish
     */
    private boolean checkForSQLInjection(HttpServletRequest request) {
        // 1. URL parametrlarini tekshirish
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String[] paramValues = request.getParameterValues(paramName);

            if (paramValues != null) {
                for (String paramValue : paramValues) {
                    if (securityService.detectSQLInjection(paramValue)) {
                        return true;
                    }

                    // Strict mode da qo'shimcha tekshiruvlar
                    if (strictMode && isStrictModeViolation(paramValue)) {
                        return true;
                    }
                }
            }
        }

        // 2. Query string ni tekshirish
        String queryString = request.getQueryString();
        if (queryString != null) {
            if (securityService.detectSQLInjection(queryString)) {
                return true;
            }
        }

        // 3. Request URI ni tekshirish
        String requestURI = request.getRequestURI();
        if (securityService.detectSQLInjection(requestURI)) {
            return true;
        }

        // 4. Ba'zi headerlarni tekshirish
        String[] headersToCheck = {"X-Forwarded-For", "X-Real-IP", "User-Agent", "Referer"};
        for (String headerName : headersToCheck) {
            String headerValue = request.getHeader(headerName);
            if (headerValue != null && securityService.detectSQLInjection(headerValue)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Strict mode da qo'shimcha tekshiruvlar
     */
    private boolean isStrictModeViolation(String input) {
        if (input == null) return false;

        String lowerInput = input.toLowerCase();

        // Xavfli SQL operatorlar
        String[] dangerousOperators = {
                "@@", "char(", "nchar(", "varchar(", "nvarchar(",
                "0x", "0X", "cast(", "convert(", "ascii(",
                "waitfor", "delay", "benchmark(", "sleep(",
                "load_file(", "into outfile", "into dumpfile"
        };

        for (String operator : dangerousOperators) {
            if (lowerInput.contains(operator)) {
                return true;
            }
        }

        // Ko'p qatordagi SQL statement lar
        if (lowerInput.contains(";") && (lowerInput.contains("select") ||
                lowerInput.contains("insert") || lowerInput.contains("update") ||
                lowerInput.contains("delete"))) {
            return true;
        }

        // Comment injection
        if (lowerInput.contains("/*") || lowerInput.contains("*/") ||
                lowerInput.contains("--") || lowerInput.contains("#")) {
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
                    if (securityService.detectSQLInjection(paramValue)) {
                        payload.append(paramName).append("=").append(paramValue).append("; ");
                    }
                }
            }
        }

        // Query string dan payload qidirish
        String queryString = request.getQueryString();
        if (queryString != null && securityService.detectSQLInjection(queryString)) {
            payload.append("QueryString: ").append(queryString).append("; ");
        }

        // URI dan payload qidirish
        String requestURI = request.getRequestURI();
        if (securityService.detectSQLInjection(requestURI)) {
            payload.append("URI: ").append(requestURI).append("; ");
        }

        return payload.length() > 0 ? payload.toString() : "SQL Injection payload detected";
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
        logger.info("SQL Injection Protection Filter to'xtatildi");
    }
}