package uz.edu.security.websecurityshield.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Foydalanuvchilar bilan ishlash uchun servis
 * Authentication Spring Security CustomUserDetailsService ga o'tkazildi
 */
@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
     * AUTHENTICATION LOGIC O'CHIRILDI!
     * Spring Security CustomUserDetailsService ishlatadi
     */

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