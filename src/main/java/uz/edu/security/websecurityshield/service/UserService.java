package uz.edu.security.websecurityshield.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Foydalanuvchilar bilan ishlash uchun servis
 */
@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SecurityService securityService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_TIME_HOURS = 1;

    /**
     * Yangi foydalanuvchi ro'yxatdan o'tkazish
     */
    public User registerUser(String username, String email, String password) {
        // Mavjudligini tekshirish
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Bu username allaqachon mavjud: " + username);
        }

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Bu email allaqachon ro'yxatdan o'tgan: " + email);
        }

        // Yangi foydalanuvchi yaratish
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());

        User savedUser = userRepository.save(user);
        logger.info("Yangi foydalanuvchi ro'yxatdan o'tdi: {}", username);

        return savedUser;
    }

    /**
     * Foydalanuvchi login qilish
     */
    public LoginResult authenticateUser(String login, String password, String ipAddress) {
        logger.info("🔍 =================================");
        logger.info("🔍 USER SERVICE - LOGIN BOSHLANDI");
        logger.info("🔍 Login: {}", login);
        logger.info("🔍 IP: {}", ipAddress);
        logger.info("🔍 =================================");

        Optional<User> userOpt = userRepository.findByUsernameOrEmail(login);

        if (userOpt.isEmpty()) {
            logger.warn("❌ Foydalanuvchi topilmadi: {}", login);
            // ... qolgan kod
            return new LoginResult(false, "Noto'g'ri login yoki parol", null);
        }

        User user = userOpt.get();
        logger.info("✅ Foydalanuvchi topildi:");
        logger.info("  - Username: {}", user.getUsername());
        logger.info("  - Email: {}", user.getEmail());
        logger.info("  - Active: {}", user.isActive());
        logger.info("  - Locked: {}", user.isAccountLocked());

        // Parol tekshirish
        boolean passwordMatch = passwordEncoder.matches(password, user.getPassword());
        logger.info("🔑 Parol tekshiruvi:");
        logger.info("  - Kiritilgan parol uzunligi: {}", password.length());
        logger.info("  - Database hash: {}", user.getPassword().substring(0, 20) + "...");
        logger.info("  - Parol mos keladimi: {}", passwordMatch);

        if (!passwordMatch) {
            logger.warn("❌ Noto'g'ri parol: {}", login);
            // ... failed login logic
            return new LoginResult(false, "Noto'g'ri login yoki parol", null);
        }

        logger.info("✅ LOGIN MUVAFFAQIYATLI: {}", user.getUsername());
        // ... successful login logic
        return new LoginResult(true, "Muvaffaqiyatli login", user);
    }

    /**
     * Muvaffaqiyatsiz login ni qayta ishlash
     */
    private void handleFailedLogin(User user, String ipAddress) {
        user.incrementFailedAttempts();

        securityService.logSecurityEvent(SecurityLog.ThreatType.FAILED_LOGIN,
                ipAddress, "/login", "Noto'g'ri parol: " + user.getUsername(), false);

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            lockUser(user);
            logger.warn("Foydalanuvchi bloklandi (ko'p noto'g'ri urinish): {}", user.getUsername());

            // IP ni ham bloklash
            securityService.blockIP(ipAddress, "Ko'p noto'g'ri login urinishlari",
                    uz.edu.security.websecurityshield.entity.BlockedIP.BlockType.AUTO_FAILED_LOGIN);
        }

        userRepository.save(user);
    }

    /**
     * Muvaffaqiyatli login ni qayta ishlash
     */
    private void handleSuccessfulLogin(User user) {
        user.setLastLogin(LocalDateTime.now());
        user.resetFailedAttempts();
        if (user.isAccountLocked()) {
            unlockUser(user);
        }
        userRepository.save(user);
    }

    /**
     * Foydalanuvchini bloklash
     */
    private void lockUser(User user) {
        user.lockAccount();
        userRepository.save(user);
    }

    /**
     * Foydalanuvchini blokdan chiqarish
     */
    private void unlockUser(User user) {
        user.unlockAccount();
        userRepository.save(user);
        logger.info("Foydalanuvchi blokdan chiqarildi: {}", user.getUsername());
    }

    /**
     * Blok muddati o'tganligini tekshirish
     */
    private boolean isLockTimeExpired(User user) {
        if (user.getLockTime() == null) return false;
        return LocalDateTime.now().isAfter(user.getLockTime().plusHours(LOCK_TIME_HOURS));
    }

    /**
     * Foydalanuvchini ID bo'yicha topish
     */
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * Foydalanuvchini username bo'yicha topish
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Barcha faol foydalanuvchilarni olish
     */
    public List<User> getAllActiveUsers() {
        return userRepository.findByActiveTrue();
    }

    /**
     * Bloklangan foydalanuvchilarni olish
     */
    public List<User> getLockedUsers() {
        return userRepository.findByAccountLockedTrue();
    }

    /**
     * Foydalanuvchi parolini o'zgartirish
     */
    public boolean changePassword(String username, String oldPassword, String newPassword) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return false;
        }

        User user = userOpt.get();

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            return false;
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        logger.info("Foydalanuvchi parolini o'zgartirdi: {}", username);
        return true;
    }

    /**
     * Foydalanuvchini faolsizlantirish
     */
    public void deactivateUser(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setActive(false);
            userRepository.save(user);
            logger.info("Foydalanuvchi faolsizlantirildi: {}", username);
        }
    }

    /**
     * Foydalanuvchini faollashtirish
     */
    public void activateUser(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setActive(true);
            user.unlockAccount(); // Blokni ham olib tashlash
            userRepository.save(user);
            logger.info("Foydalanuvchi faollashtirildi: {}", username);
        }
    }

    /**
     * Muddati o'tgan bloklangan foydalanuvchilarni avtomatik blokdan chiqarish
     */
    public void unlockExpiredUsers() {
        LocalDateTime expireTime = LocalDateTime.now().minusHours(LOCK_TIME_HOURS);
        List<User> expiredUsers = userRepository.findExpiredLockedUsers(expireTime);

        for (User user : expiredUsers) {
            unlockUser(user);
        }

        if (!expiredUsers.isEmpty()) {
            logger.info("Muddati o'tgan {} ta foydalanuvchi blokdan chiqarildi", expiredUsers.size());
        }
    }

    /**
     * Foydalanuvchilar statistikasi
     */
    public UserStats getUserStats() {
        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countActiveUsers();
        long lockedUsers = userRepository.findByAccountLockedTrue().size();
        long todayRegistrations = userRepository.countUsersRegisteredSince(
                LocalDateTime.now().withHour(0).withMinute(0).withSecond(0));

        return new UserStats(totalUsers, activeUsers, lockedUsers, todayRegistrations);
    }

    // Login natijasi klassi
    public static class LoginResult {
        public final boolean success;
        public final String message;
        public final User user;

        public LoginResult(boolean success, String message, User user) {
            this.success = success;
            this.message = message;
            this.user = user;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
    }

    // Foydalanuvchilar statistikasi klassi
    public static class UserStats {
        public final long totalUsers;
        public final long activeUsers;
        public final long lockedUsers;
        public final long todayRegistrations;

        public UserStats(long totalUsers, long activeUsers, long lockedUsers, long todayRegistrations) {
            this.totalUsers = totalUsers;
            this.activeUsers = activeUsers;
            this.lockedUsers = lockedUsers;
            this.todayRegistrations = todayRegistrations;
        }
    }
}