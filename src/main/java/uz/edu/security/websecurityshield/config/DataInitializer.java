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
 * Dastur ishga tushganda test ma'lumotlarini yaratuvchi klass - DEBUG VERSION
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
        logger.info("🚀 DataInitializer ishga tushdi!");
        logger.info("🚀 Ma'lumotlar bazasini boshlang'ich ma'lumotlar bilan to'ldirish...");

        try {
            // Repository larni tekshirish
            logger.info("📊 Repositories tekshirish:");
            logger.info("  - UserRepository: {}", userRepository != null ? "OK" : "NULL");
            logger.info("  - SecurityLogRepository: {}", securityLogRepository != null ? "OK" : "NULL");
            logger.info("  - BlockedIPRepository: {}", blockedIPRepository != null ? "OK" : "NULL");
            logger.info("  - PasswordEncoder: {}", passwordEncoder != null ? "OK" : "NULL");

            // User count tekshirish
            long userCount = userRepository.count();
            logger.info("📊 Mavjud foydalanuvchilar soni: {}", userCount);

            createTestUsers();
            createSampleSecurityLogs();
            createSampleBlockedIPs();

            logger.info("✅ Test ma'lumotlari muvaffaqiyatli yaratildi!");
            printLoginInstructions();

        } catch (Exception e) {
            logger.error("❌ DataInitializer da xatolik: ", e);
            throw e;
        }
    }

    /**
     * Test foydalanuvchilarini yaratish
     */
    private void createTestUsers() {
        logger.info("👤 Test foydalanuvchilarini yaratish...");

        try {
            // Admin foydalanuvchisini yaratish
            boolean adminExists = userRepository.existsByUsername("admin");
            logger.info("🔍 Admin mavjudmi: {}", adminExists);

            if (!adminExists) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setEmail("admin@security.uz");
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setActive(true);
                admin.setCreatedAt(LocalDateTime.now());

                User savedAdmin = userRepository.save(admin);
                logger.info("✅ Admin foydalanuvchisi yaratildi: admin / admin123 (ID: {})", savedAdmin.getId());
            } else {
                logger.info("ℹ️ Admin foydalanuvchisi allaqachon mavjud");
            }

            // Test foydalanuvchisini yaratish
            boolean testExists = userRepository.existsByUsername("test");
            logger.info("🔍 Test user mavjudmi: {}", testExists);

            if (!testExists) {
                User testUser = new User();
                testUser.setUsername("test");
                testUser.setEmail("test@security.uz");
                testUser.setPassword(passwordEncoder.encode("test123"));
                testUser.setActive(true);
                testUser.setCreatedAt(LocalDateTime.now());

                User savedTest = userRepository.save(testUser);
                logger.info("✅ Test foydalanuvchisi yaratildi: test / test123 (ID: {})", savedTest.getId());
            } else {
                logger.info("ℹ️ Test foydalanuvchisi allaqachon mavjud");
            }

            // Yaratilgan foydalanuvchilarni tekshirish
            long finalUserCount = userRepository.count();
            logger.info("📊 Jami foydalanuvchilar soni: {}", finalUserCount);

            // Barcha foydalanuvchilarni ko'rsatish
            userRepository.findAll().forEach(user -> {
                logger.info("👤 Foydalanuvchi: {} ({})", user.getUsername(), user.getEmail());
            });

        } catch (Exception e) {
            logger.error("❌ Test foydalanuvchilarini yaratishda xatolik: ", e);
            throw e;
        }
    }

    /**
     * Namuna xavfsizlik loglarini yaratish
     */
    private void createSampleSecurityLogs() {
        logger.info("📋 Namuna xavfsizlik loglarini yaratish...");

        try {
            if (securityLogRepository.count() == 0) {
                // XSS hujumi
                SecurityLog xssLog = new SecurityLog(
                        SecurityLog.ThreatType.XSS_ATTACK,
                        "203.0.113.10",
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
                        "203.0.113.20",
                        "SQL Injection hujumi aniqlandi"
                );
                sqlLog.setRequestUrl("/user?id=1' OR '1'='1");
                sqlLog.setRequestMethod("GET");
                sqlLog.setAttackPayload("1' OR '1'='1");
                sqlLog.setBlocked(true);
                sqlLog.setUserAgent("sqlmap/1.0");
                securityLogRepository.save(sqlLog);

                logger.info("✅ {} ta namuna xavfsizlik logi yaratildi", 2);
            } else {
                logger.info("ℹ️ Xavfsizlik loglari allaqachon mavjud");
            }
        } catch (Exception e) {
            logger.error("❌ Xavfsizlik loglarini yaratishda xatolik: ", e);
        }
    }

    /**
     * Namuna bloklangan IP larni yaratish
     */
    private void createSampleBlockedIPs() {
        logger.info("🚫 Namuna bloklangan IP larni yaratish...");

        try {
            if (blockedIPRepository.count() == 0) {
                // Doimiy bloklangan IP
                BlockedIP permanentBlock = new BlockedIP(
                        "203.0.113.10",
                        "Ko'p marta XSS hujumi amalga oshirgan",
                        BlockedIP.BlockType.AUTO_ATTACK
                );
                permanentBlock.setPermanent(true);
                permanentBlock.setBlockCount(5);
                blockedIPRepository.save(permanentBlock);

                logger.info("✅ {} ta namuna bloklangan IP yaratildi", 1);
            } else {
                logger.info("ℹ️ Bloklangan IP lar allaqachon mavjud");
            }
        } catch (Exception e) {
            logger.error("❌ Bloklangan IP larni yaratishda xatolik: ", e);
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

        // Qo'shimcha debug ma'lumot
        logger.info("🔧 DEBUG MA'LUMOTLARI:");
        logger.info("  - Jami users: {}", userRepository.count());
        logger.info("  - Jami logs: {}", securityLogRepository.count());
        logger.info("  - Jami blocked IPs: {}", blockedIPRepository.count());
        logger.info("=================================");
    }
}