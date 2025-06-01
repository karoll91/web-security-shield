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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate Limiting (so'rovlar cheklash) filter
 */
@Component
public class RateLimitFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    @Autowired
    private SecurityService securityService;

    @Value("${security.rate-limit.requests-per-minute:10}")
    private int maxRequestsPerMinute;

    @Value("${security.rate-limit.block-duration-minutes:5}")
    private int blockDurationMinutes;

    // IP manzillar uchun request counter
    private final ConcurrentHashMap<String, RequestCounter> requestCounters = new ConcurrentHashMap<>();

    // Timeout uchun vaqt (milliseconds)
    private static final long WINDOW_SIZE = 60 * 1000; // 1 minut

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("Rate Limit Filter ishga tushdi. Max requests/min: {}, Block duration: {} min",
                maxRequestsPerMinute, blockDurationMinutes);

        // Eski counterlarni tozalash uchun thread
        startCleanupThread();
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String ipAddress = getClientIpAddress(request);
        String requestUrl = request.getRequestURL().toString();

        // Static fayllar uchun rate limit qo'llamaymiz
        if (isStaticResource(requestUrl)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        // Localhost IP lar uchun rate limit qo'llamaymiz
        if (isLocalhostIP(ipAddress)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        // IP bloklanganligini tekshirish
        if (securityService.isIPBlocked(ipAddress)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"IP bloklangan\",\"code\":\"IP_BLOCKED\"}");
            return;
        }

        // Rate limit tekshirish
        if (!checkRateLimit(ipAddress)) {
            logger.warn("Rate limit oshdi! IP: {}, URL: {}", ipAddress, requestUrl);

            // Hujumni qayta ishlash
            securityService.handleSecurityThreat(
                    SecurityLog.ThreatType.RATE_LIMIT_EXCEEDED,
                    ipAddress,
                    requestUrl,
                    "Rate limit exceeded: " + maxRequestsPerMinute + " requests/min"
            );

            // 429 Too Many Requests
            response.setStatus(429);
            response.setContentType("application/json");
            response.setHeader("Retry-After", String.valueOf(blockDurationMinutes * 60));
            response.getWriter().write("{\"error\":\"Juda ko'p so'rov. Keyinroq urinib ko'ring.\",\"code\":\"RATE_LIMIT_EXCEEDED\"}");
            return;
        }

        // Rate limit OK - davom etish
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * Localhost IP ekanligini tekshirish
     */
    private boolean isLocalhostIP(String ipAddress) {
        return ipAddress != null && (
                ipAddress.equals("127.0.0.1") ||
                        ipAddress.equals("0:0:0:0:0:0:0:1") ||
                        ipAddress.equals("::1") ||
                        ipAddress.equals("localhost") ||
                        ipAddress.startsWith("192.168.") ||
                        ipAddress.startsWith("10.") ||
                        ipAddress.startsWith("172.")
        );
    }

    /**
     * Rate limit tekshirish va yangilash
     */
    private boolean checkRateLimit(String ipAddress) {
        long currentTime = System.currentTimeMillis();

        RequestCounter counter = requestCounters.computeIfAbsent(ipAddress,
                k -> new RequestCounter(currentTime));

        synchronized (counter) {
            // Agar window muddati o'tgan bo'lsa, counterni reset qilish
            if (currentTime - counter.windowStart > WINDOW_SIZE) {
                counter.reset(currentTime);
            }

            // Request sonini oshirish
            counter.increment();

            // Limit oshganligini tekshirish - get() metodini ishlatish
            return counter.count.get() <= maxRequestsPerMinute;
        }
    }

    /**
     * Static fayllarni aniqlash
     */
    private boolean isStaticResource(String url) {
        String[] staticExtensions = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"};

        String lowerUrl = url.toLowerCase();
        for (String ext : staticExtensions) {
            if (lowerUrl.endsWith(ext)) {
                return true;
            }
        }

        return lowerUrl.contains("/static/") || lowerUrl.contains("/css/") ||
                lowerUrl.contains("/js/") || lowerUrl.contains("/images/");
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

    /**
     * Eski counterlarni tozalash thread
     */
    private void startCleanupThread() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(5 * 60 * 1000); // 5 minut
                    cleanOldCounters();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });

        cleanupThread.setDaemon(true);
        cleanupThread.setName("RateLimit-Cleanup");
        cleanupThread.start();
    }

    /**
     * Eski counterlarni tozalash
     */
    private void cleanOldCounters() {
        long currentTime = System.currentTimeMillis();
        long expireTime = 10 * 60 * 1000; // 10 minut

        requestCounters.entrySet().removeIf(entry -> {
            RequestCounter counter = entry.getValue();
            return (currentTime - counter.windowStart) > expireTime;
        });

        logger.debug("Eski rate limit counterlar tozalandi. Hozirgi faol IP lar: {}",
                requestCounters.size());
    }

    /**
     * Rate limit ma'lumotlarini olish (monitoring uchun)
     */
    public RateLimitStats getRateLimitStats() {
        return new RateLimitStats(
                requestCounters.size(),
                maxRequestsPerMinute,
                blockDurationMinutes
        );
    }

    @Override
    public void destroy() {
        requestCounters.clear();
        logger.info("Rate Limit Filter to'xtatildi");
    }

    /**
     * Request counter klassi
     */
    private static class RequestCounter {
        volatile long windowStart;
        final AtomicInteger count;

        RequestCounter(long windowStart) {
            this.windowStart = windowStart;
            this.count = new AtomicInteger(0);
        }

        void reset(long newWindowStart) {
            this.windowStart = newWindowStart;
            this.count.set(0);
        }

        void increment() {
            this.count.incrementAndGet();
        }
    }

    /**
     * Rate limit statistika klassi
     */
    public static class RateLimitStats {
        public final int activeIPs;
        public final int maxRequestsPerMinute;
        public final int blockDurationMinutes;

        public RateLimitStats(int activeIPs, int maxRequestsPerMinute, int blockDurationMinutes) {
            this.activeIPs = activeIPs;
            this.maxRequestsPerMinute = maxRequestsPerMinute;
            this.blockDurationMinutes = blockDurationMinutes;
        }
    }
}