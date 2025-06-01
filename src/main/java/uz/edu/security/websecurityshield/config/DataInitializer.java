package uz.edu.security.websecurityshield.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import uz.edu.security.websecurityshield.entity.BlockedIP;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.repository.BlockedIPRepository;
import uz.edu.security.websecurityshield.repository.SecurityLogRepository;
import uz.edu.security.websecurityshield.repository.UserRepository;

import java.time.LocalDateTime;

/**
 * Dastur ishga tushganda test ma'lumotlarini yaratuvchi klass
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Autowired
    private BlockedIPRepository blockedIPRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        logger.info("🚀 Ma'lumotlar bazasini boshlang'ich ma'lumotlar bilan to'ldirish...");

        createTestUsers();
        createSampleSecurityLogs();
        createSampleBlockedIPs();

        logger.info("✅ Test ma'lumotlari muvaffaqiyatli yaratildi!");
        printLoginInstructions();
    }

    /**
     * Test foydalanuvchilarini yaratish
     */
    private void createTestUsers() {
        // Admin foydalanuvchisini yaratish
        if (!userRepository.existsByUsername("admin")) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@security.uz");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setActive(true);
            admin.setCreatedAt(LocalDateTime.now());

            userRepository.save(admin);
            logger.info("✅ Admin foydalanuvchisi yaratildi: admin / admin123");
        }

        // Test foydalanuvchisini yaratish
        if (!userRepository.existsByUsername("test")) {
            User testUser = new User();
            testUser.setUsername("test");
            testUser.setEmail("test@security.uz");
            testUser.setPassword(passwordEncoder.encode("test123"));
            testUser.setActive(true);
            testUser.setCreatedAt(LocalDateTime.now());

            userRepository.save(testUser);
            logger.info("✅ Test foydalanuvchisi yaratildi: test / test123");
        }
    }

    /**
     * Namuna xavfsizlik loglarini yaratish
     */
    private void createSampleSecurityLogs() {
        if (securityLogRepository.count() == 0) {
            // XSS hujumi
            SecurityLog xssLog = new SecurityLog(
                    SecurityLog.ThreatType.XSS_ATTACK,
                    "203.0.113.10", // Test IP (RFC 5737)
                    "XSS hujumi aniqlandi"
            );
            xssLog.setRequestUrl("/search?q=<script>alert('xss')</script>");
            xssLog.setRequestMethod("GET");
            xssLog.setAttackPayload("<script>alert('xss')</script>");
            xssLog.setBlocked(true);
            xssLog.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            securityLogRepository.save(xssLog);

            // SQL Injection hujumi
            SecurityLog sqlLog = new SecurityLog(
                    SecurityLog.ThreatType.SQL_INJECTION,
                    "203.0.113.20", // Test IP
                    "SQL Injection hujumi aniqlandi"
            );
            sqlLog.setRequestUrl("/user?id=1' OR '1'='1");
            sqlLog.setRequestMethod("GET");
            sqlLog.setAttackPayload("1' OR '1'='1");
            sqlLog.setBlocked(true);
            sqlLog.setUserAgent("sqlmap/1.0");
            securityLogRepository.save(sqlLog);

            // Rate limit hujumi
            SecurityLog rateLog = new SecurityLog(
                    SecurityLog.ThreatType.RATE_LIMIT_EXCEEDED,
                    "203.0.113.30", // Test IP
                    "Rate limit oshib ketdi"
            );
            rateLog.setRequestUrl("/api/data");
            rateLog.setRequestMethod("POST");
            rateLog.setAttackPayload("15 requests in 1 minute");
            rateLog.setBlocked(true);
            rateLog.setUserAgent("Python-requests/2.25.1");
            securityLogRepository.save(rateLog);

            // Brute force hujumi
            SecurityLog bruteLog = new SecurityLog(
                    SecurityLog.ThreatType.BRUTE_FORCE,
                    "203.0.113.40", // Test IP
                    "Brute force hujumi aniqlandi"
            );
            bruteLog.setRequestUrl("/login");
            bruteLog.setRequestMethod("POST");
            bruteLog.setAttackPayload("Multiple failed login attempts");
            bruteLog.setBlocked(true);
            bruteLog.setUserAgent("Hydra/9.0");
            securityLogRepository.save(bruteLog);

            // Shubhali so'rov
            SecurityLog suspiciousLog = new SecurityLog(
                    SecurityLog.ThreatType.SUSPICIOUS_REQUEST,
                    "203.0.113.50", // Test IP
                    "Shubhali faoliyat aniqlandi"
            );
            suspiciousLog.setRequestUrl("/admin/config");
            suspiciousLog.setRequestMethod("GET");
            suspiciousLog.setAttackPayload("Unauthorized access attempt");
            suspiciousLog.setBlocked(false);
            suspiciousLog.setUserAgent("Nmap Scripting Engine");
            securityLogRepository.save(suspiciousLog);

            logger.info("✅ {} ta namuna xavfsizlik logi yaratildi", 5);
        }
    }

    /**
     * Namuna bloklangan IP larni yaratish
     */
    private void createSampleBlockedIPs() {
        if (blockedIPRepository.count() == 0) {
            // Doimiy bloklangan IP
            BlockedIP permanentBlock = new BlockedIP(
                    "203.0.113.10", // Test IP
                    "Ko'p marta XSS hujumi amalga oshirgan",
                    BlockedIP.BlockType.AUTO_ATTACK
            );
            permanentBlock.setPermanent(true);
            permanentBlock.setBlockCount(5);
            blockedIPRepository.save(permanentBlock);

            // Vaqtinchalik bloklangan IP
            BlockedIP temporaryBlock = new BlockedIP(
                    "203.0.113.20", // Test IP
                    "SQL Injection hujumi",
                    BlockedIP.BlockType.AUTO_ATTACK,
                    24 // 24 soat
            );
            temporaryBlock.setBlockCount(2);
            blockedIPRepository.save(temporaryBlock);

            // Rate limit uchun bloklangan IP
            BlockedIP rateLimitBlock = new BlockedIP(
                    "203.0.113.30", // Test IP
                    "Rate limit oshib ketdi",
                    BlockedIP.BlockType.AUTO_RATE_LIMIT,
                    1 // 1 soat
            );
            rateLimitBlock.setBlockCount(1);
            blockedIPRepository.save(rateLimitBlock);

            // Qo'lda bloklangan IP
            BlockedIP manualBlock = new BlockedIP(
                    "203.0.113.100", // Test IP
                    "Administrator tomonidan qo'lda bloklangan",
                    BlockedIP.BlockType.MANUAL
            );
            manualBlock.setPermanent(true);
            manualBlock.setBlockCount(1);
            blockedIPRepository.save(manualBlock);

            logger.info("✅ {} ta namuna bloklangan IP yaratildi", 4);
        }
    }

    /**
     * Login ma'lumotlarini ko'rsatish
     */
    private void printLoginInstructions() {
        logger.info("");
        logger.info("🔐 LOGIN MA'LUMOTLARI:");
        logger.info("=================================");
        logger.info("URL: http://localhost:8080");
        logger.info("");
        logger.info("Admin foydalanuvchi:");
        logger.info("  Username: admin");
        logger.info("  Password: admin123");
        logger.info("");
        logger.info("Test foydalanuvchi:");
        logger.info("  Username: test");
        logger.info("  Password: test123");
        logger.info("");
        logger.info("H2 Database Console:");
        logger.info("  URL: http://localhost:8080/h2-console");
        logger.info("  JDBC URL: jdbc:h2:mem:security_db");
        logger.info("  Username: sa");
        logger.info("  Password: (bo'sh)");
        logger.info("=================================");
        logger.info("");
    }
}