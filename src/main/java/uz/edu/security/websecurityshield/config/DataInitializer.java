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
 * DEBUG VERSION - Password encoding bilan muammolarni topish
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
        logger.info("🚀 ==============================================");
        logger.info("🚀 DataInitializer DEBUG VERSION");
        logger.info("🚀 ==============================================");

        try {
            // Password encoder test
            testPasswordEncoder();

            // Repositories test
            testRepositories();

            // Users yaratish
            createTestUsers();

            // Other data
            createSampleSecurityLogs();
            createSampleBlockedIPs();

            logger.info("✅ DataInitializer muvaffaqiyatli tugadi!");
            printFinalStats();

        } catch (Exception e) {
            logger.error("❌ DataInitializer da xatolik: ", e);
            throw e;
        }
    }

    private void testPasswordEncoder() {
        logger.info("🔐 PasswordEncoder testlari:");

        String rawPassword = "admin123";
        String encodedPassword = passwordEncoder.encode(rawPassword);
        boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);

        logger.info("   - Raw password: '{}'", rawPassword);
        logger.info("   - Encoded password: '{}'", encodedPassword);
        logger.info("   - Matches test: {}", matches);

        if (!matches) {
            logger.error("❌ CRITICAL: PasswordEncoder ishlamayapti!");
            throw new RuntimeException("PasswordEncoder failed");
        }

        logger.info("✅ PasswordEncoder ishlayapti");
    }

    private void testRepositories() {
        logger.info("📊 Repository testlari:");
        logger.info("   - UserRepository: {}", userRepository != null ? "OK" : "NULL");
        logger.info("   - SecurityLogRepository: {}", securityLogRepository != null ? "OK" : "NULL");
        logger.info("   - BlockedIPRepository: {}", blockedIPRepository != null ? "OK" : "NULL");
        logger.info("   - PasswordEncoder: {}", passwordEncoder != null ? "OK" : "NULL");

        long userCount = userRepository.count();
        logger.info("   - Mavjud userlar soni: {}", userCount);
    }

    private void createTestUsers() {
        logger.info("👤 Test userlarini yaratish...");

        // Admin user
        createUserIfNotExists("admin", "admin@security.uz", "admin123");

        // Test user
        createUserIfNotExists("test", "test@security.uz", "test123");

        // Test qilish uchun qo'shimcha userlar
        createUserIfNotExists("user1", "user1@test.com", "password123");
        createUserIfNotExists("demo", "demo@test.com", "demo123");
    }

    private void createUserIfNotExists(String username, String email, String rawPassword) {
        logger.info("🔍 User yaratish: username='{}', email='{}'", username, email);

        boolean existsByUsername = userRepository.existsByUsername(username);
        boolean existsByEmail = userRepository.existsByEmail(email);

        logger.info("   - Username '{}' mavjudmi: {}", username, existsByUsername);
        logger.info("   - Email '{}' mavjudmi: {}", email, existsByEmail);

        if (existsByUsername || existsByEmail) {
            logger.info("   - User allaqachon mavjud, o'tkazib yuborish");
            return;
        }

        try {
            // Password encode qilish
            String encodedPassword = passwordEncoder.encode(rawPassword);
            logger.info("   - Raw password: '{}'", rawPassword);
            logger.info("   - Encoded password: '{}'", encodedPassword);

            // Encoding testlari
            boolean encodeTest = passwordEncoder.matches(rawPassword, encodedPassword);
            logger.info("   - Encode test: {}", encodeTest);

            if (!encodeTest) {
                logger.error("❌ Password encoding muvaffaqiyatsiz!");
                throw new RuntimeException("Password encoding failed for " + username);
            }

            // User yaratish
            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setPassword(encodedPassword);
            user.setActive(true);
            user.setCreatedAt(LocalDateTime.now());

            User savedUser = userRepository.save(user);
            logger.info("✅ User yaratildi: ID={}, username='{}', email='{}'",
                    savedUser.getId(), savedUser.getUsername(), savedUser.getEmail());

            // Qayta o'qish va tekshirish
            User retrievedUser = userRepository.findById(savedUser.getId()).orElse(null);
            if (retrievedUser != null) {
                logger.info("   - Database dan o'qildi: username='{}', password='{}'",
                        retrievedUser.getUsername(), retrievedUser.getPassword());

                // Password test
                boolean passwordTest = passwordEncoder.matches(rawPassword, retrievedUser.getPassword());
                logger.info("   - Password test (database dan): {}", passwordTest);

                if (!passwordTest) {
                    logger.error("❌ CRITICAL: Database ga saqlangan password noto'g'ri!");
                }
            }

        } catch (Exception e) {
            logger.error("❌ User yaratishda xatolik: ", e);
            throw e;
        }
    }

    private void createSampleSecurityLogs() {
        logger.info("📋 Namuna xavfsizlik loglarini yaratish...");

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
        }
    }

    private void createSampleBlockedIPs() {
        logger.info("🚫 Namuna bloklangan IP larni yaratish...");

        if (blockedIPRepository.count() == 0) {
            BlockedIP permanentBlock = new BlockedIP(
                    "203.0.113.10",
                    "Ko'p marta XSS hujumi amalga oshirgan",
                    BlockedIP.BlockType.AUTO_ATTACK
            );
            permanentBlock.setPermanent(true);
            permanentBlock.setBlockCount(5);
            blockedIPRepository.save(permanentBlock);

            logger.info("✅ {} ta namuna bloklangan IP yaratildi", 1);
        }
    }

    private void printFinalStats() {
        logger.info("🔍 ==============================================");
        logger.info("🔍 FINAL STATISTICS");
        logger.info("🔍 ==============================================");

        long totalUsers = userRepository.count();
        logger.info("📊 Jami userlar: {}", totalUsers);

        // Barcha userlarni ko'rsatish
        userRepository.findAll().forEach(user -> {
            logger.info("👤 User: ID={}, username='{}', email='{}', active={}",
                    user.getId(), user.getUsername(), user.getEmail(), user.isActive());
            logger.info("    Password hash: '{}'", user.getPassword());

            // Password test
            boolean adminTest = passwordEncoder.matches("admin123", user.getPassword());
            boolean testTest = passwordEncoder.matches("test123", user.getPassword());
            logger.info("    admin123 test: {}", adminTest);
            logger.info("    test123 test: {}", testTest);
        });

        logger.info("📊 Jami logs: {}", securityLogRepository.count());
        logger.info("📊 Jami blocked IPs: {}", blockedIPRepository.count());

        logger.info("🔍 ==============================================");
        logger.info("🔐 LOGIN MA'LUMOTLARI:");
        logger.info("🔐 URL: http://localhost:8080/login");
        logger.info("🔐 admin / admin123");
        logger.info("🔐 test / test123");
        logger.info("🔍 ==============================================");
    }
}