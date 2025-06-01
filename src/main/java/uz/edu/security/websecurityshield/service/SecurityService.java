package uz.edu.security.websecurityshield.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uz.edu.security.websecurityshield.entity.BlockedIP;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.repository.BlockedIPRepository;
import uz.edu.security.websecurityshield.repository.SecurityLogRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Asosiy xavfsizlik operatsiyalarini boshqaruvchi servis
 */
@Service
@Transactional
public class SecurityService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityService.class);

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Autowired
    private BlockedIPRepository blockedIPRepository;

    // Sozlamalar
    @Value("${security.rate-limit.requests-per-minute:10}")
    private int maxRequestsPerMinute;

    @Value("${security.rate-limit.block-duration-minutes:5}")
    private int rateLimitBlockDuration;

    @Value("${security.ip-blocking.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.ip-blocking.block-duration-hours:1}")
    private int ipBlockDurationHours;

    // XSS Pattern lar
    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<iframe[^>]*>.*?</iframe>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<img[^>]*onerror[^>]*>", Pattern.CASE_INSENSITIVE)
    };

    // SQL Injection Pattern lar
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
            Pattern.compile("('|(\\-\\-)|(;)|(\\|)|(\\*)|(%))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(union|select|insert|delete|update|drop|create|alter)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(exec|execute|sp_|xp_)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(script|vbscript)", Pattern.CASE_INSENSITIVE)
    };

    /**
     * XSS hujumini aniqlash
     */
    public boolean detectXSS(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warn("XSS hujumi aniqlandi: {}", input);
                return true;
            }
        }
        return false;
    }

    /**
     * SQL Injection hujumini aniqlash
     */
    public boolean detectSQLInjection(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warn("SQL Injection hujumi aniqlandi: {}", input);
                return true;
            }
        }
        return false;
    }

    /**
     * Rate Limiting tekshirish
     */
    public boolean checkRateLimit(String ipAddress) {
        LocalDateTime oneMinuteAgo = LocalDateTime.now().minusMinutes(1);
        long requestCount = securityLogRepository.countAttacksByIpSince(ipAddress, oneMinuteAgo);

        if (requestCount >= maxRequestsPerMinute) {
            logger.warn("Rate limit oshdi IP: {} - {} requests", ipAddress, requestCount);
            return false;
        }
        return true;
    }

    /**
     * IP manzilni bloklash
     */
    public void blockIP(String ipAddress, String reason, BlockedIP.BlockType blockType) {
        Optional<BlockedIP> existingBlock = blockedIPRepository.findByIpAddress(ipAddress);

        if (existingBlock.isPresent()) {
            // Mavjud blokni uzaytirish
            BlockedIP blocked = existingBlock.get();
            blocked.extendBlock(ipBlockDurationHours);
            blockedIPRepository.save(blocked);
            logger.info("IP blok muddati uzaytirildi: {} - {}", ipAddress, reason);
        } else {
            // Yangi blok yaratish
            BlockedIP newBlock = new BlockedIP(ipAddress, reason, blockType, ipBlockDurationHours);
            blockedIPRepository.save(newBlock);
            logger.info("IP bloklandi: {} - {}", ipAddress, reason);
        }
    }

    /**
     * IP bloklanganligini tekshirish (localhost uchun exception)
     */
    public boolean isIPBlocked(String ipAddress) {
        // Localhost IP larni hech qachon bloklamaslik
        if (isLocalhostIP(ipAddress)) {
            return false;
        }

        return blockedIPRepository.isIpActivelyBlocked(ipAddress, LocalDateTime.now());
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
     * Xavfsizlik hodisasini log qilish
     */
    @Async
    public void logSecurityEvent(SecurityLog.ThreatType threatType, String ipAddress,
                                 String requestUrl, String attackPayload, boolean blocked) {
        SecurityLog log = new SecurityLog(threatType, ipAddress,
                "Hujum aniqlandi: " + threatType.getDisplayName());
        log.setRequestUrl(requestUrl);
        log.setAttackPayload(attackPayload);
        log.setBlocked(blocked);
        log.setRequestMethod("GET"); // Default qiymat

        securityLogRepository.save(log);
        logger.info("Xavfsizlik hodisasi saqlandi: {} - IP: {}", threatType, ipAddress);
    }

    /**
     * Hujumni qayta ishlash va kerakli choralarni ko'rish
     */
    public boolean handleSecurityThreat(SecurityLog.ThreatType threatType, String ipAddress,
                                        String requestUrl, String payload) {

        // 1. Hodisani log qilish
        logSecurityEvent(threatType, ipAddress, requestUrl, payload, false);

        // 2. IP bloklanganligini tekshirish
        if (isIPBlocked(ipAddress)) {
            logger.info("Bloklangan IP dan so'rov: {}", ipAddress);
            return true; // Bloklash
        }

        // 3. Threat type ga qarab harakat qilish
        boolean shouldBlock = false;

        switch (threatType) {
            case XSS_ATTACK, SQL_INJECTION -> {
                // Kritik hujumlar - darhol bloklash
                blockIP(ipAddress, "Kritik hujum: " + threatType.getDisplayName(),
                        BlockedIP.BlockType.AUTO_ATTACK);
                shouldBlock = true;
            }
            case RATE_LIMIT_EXCEEDED -> {
                // Rate limit oshdi - vaqtinchalik bloklash
                blockIP(ipAddress, "Rate limit oshdi", BlockedIP.BlockType.AUTO_RATE_LIMIT);
                shouldBlock = true;
            }
            case FAILED_LOGIN -> {
                // Noto'g'ri login urinishlari
                LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
                long failedAttempts = securityLogRepository.countAttacksByIpSince(ipAddress, oneHourAgo);

                if (failedAttempts >= maxFailedAttempts) {
                    blockIP(ipAddress, "Ko'p noto'g'ri login urinishlari",
                            BlockedIP.BlockType.AUTO_FAILED_LOGIN);
                    shouldBlock = true;
                }
            }
            case SUSPICIOUS_REQUEST -> {
                // Shubhali so'rovlar - kuzatish
                logger.warn("Shubhali so'rov IP dan: {}", ipAddress);
            }
        }

        // 4. Agar blok qilindigan bo'lsa, log ni yangilash
        if (shouldBlock) {
            logSecurityEvent(threatType, ipAddress, requestUrl, payload, true);
        }

        return shouldBlock;
    }

    /**
     * IP blokdan chiqarish
     */
    public void unblockIP(String ipAddress) {
        Optional<BlockedIP> blocked = blockedIPRepository.findByIpAddress(ipAddress);
        if (blocked.isPresent()) {
            blockedIPRepository.delete(blocked.get());
            logger.info("IP blokdan chiqarildi: {}", ipAddress);
        }
    }

    /**
     * Muddati o'tgan bloklarni tozalash (har 5 daqiqada)
     */
    @Scheduled(fixedRate = 300000) // 5 minut
    public void cleanExpiredBlocks() {
        int deletedCount = blockedIPRepository.deleteExpiredBlocks(LocalDateTime.now());
        if (deletedCount > 0) {
            logger.info("Muddati o'tgan {} ta blok tozalandi", deletedCount);
        }
    }

    /**
     * Eski loglarni tozalash (har kuni)
     */
    @Scheduled(cron = "0 0 2 * * ?") // Har kuni soat 2:00 da
    public void cleanOldLogs() {
        LocalDateTime oneMonthAgo = LocalDateTime.now().minusMonths(1);
        List<SecurityLog> oldLogs = securityLogRepository.findLogsBetweenDates(
                LocalDateTime.now().minusYears(10), oneMonthAgo);

        if (!oldLogs.isEmpty()) {
            securityLogRepository.deleteAll(oldLogs);
            logger.info("Eski {} ta log tozalandi", oldLogs.size());
        }
    }

    /**
     * Xavfsizlik statistikasini olish
     */
    public SecurityStats getSecurityStats() {
        LocalDateTime dayAgo = LocalDateTime.now().minusHours(24);
        LocalDateTime weekAgo = LocalDateTime.now().minusDays(7);

        // Kritik hujumlar uchun severity list
        List<SecurityLog.Severity> criticalSeverities = List.of(
                SecurityLog.Severity.HIGH,
                SecurityLog.Severity.CRITICAL
        );

        long criticalAttacks = securityLogRepository
                .findBySeverityInAndTimestampGreaterThanEqualOrderByTimestampDesc(criticalSeverities, dayAgo)
                .size();

        return new SecurityStats(
                securityLogRepository.count(),
                securityLogRepository.findLogsBetweenDates(dayAgo, LocalDateTime.now()).size(),
                securityLogRepository.findLogsBetweenDates(weekAgo, LocalDateTime.now()).size(),
                blockedIPRepository.countActiveBlocks(LocalDateTime.now()),
                criticalAttacks
        );
    }

    // Statistika klassı
    public static class SecurityStats {
        public final long totalLogs;
        public final long todayAttacks;
        public final long weeklyAttacks;
        public final long activeBlocks;
        public final long criticalAttacks;

        public SecurityStats(long totalLogs, long todayAttacks, long weeklyAttacks,
                             long activeBlocks, long criticalAttacks) {
            this.totalLogs = totalLogs;
            this.todayAttacks = todayAttacks;
            this.weeklyAttacks = weeklyAttacks;
            this.activeBlocks = activeBlocks;
            this.criticalAttacks = criticalAttacks;
        }
    }
}