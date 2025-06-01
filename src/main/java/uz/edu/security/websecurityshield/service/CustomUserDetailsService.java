package uz.edu.security.websecurityshield.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.repository.UserRepository;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * DEBUG VERSION - Spring Security UserDetailsService implementation
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        logger.info("🔍 ==============================================");
        logger.info("🔍 UserDetailsService - loadUserByUsername CALLED");
        logger.info("🔍 Input parameter: '{}'", usernameOrEmail);
        logger.info("🔍 ==============================================");

        // 1. Database dan userlarni tekshirish
        logger.info("📊 Database da jami userlar soni: {}", userRepository.count());

        // Barcha userlarni ko'rsatish (debug uchun)
        userRepository.findAll().forEach(u -> {
            logger.info("👤 DB User: username='{}', email='{}', active={}",
                    u.getUsername(), u.getEmail(), u.isActive());
        });

        // 2. findByUsernameOrEmail metodini sinash
        logger.info("🔍 findByUsernameOrEmail('{}') ni chaqirish...", usernameOrEmail);

        Optional<User> userOpt;
        try {
            userOpt = userRepository.findByUsernameOrEmail(usernameOrEmail);
            logger.info("✅ findByUsernameOrEmail natijasi: {}", userOpt.isPresent() ? "TOPILDI" : "TOPILMADI");
        } catch (Exception e) {
            logger.error("❌ findByUsernameOrEmail da xatolik: ", e);
            throw new UsernameNotFoundException("Database error: " + e.getMessage());
        }

        // 3. User topilmasa, boshqa usullarni sinash
        if (userOpt.isEmpty()) {
            logger.warn("❌ findByUsernameOrEmail bilan topilmadi, boshqa usullar sinash...");

            // Username bo'yicha sinash
            Optional<User> byUsername = userRepository.findByUsername(usernameOrEmail);
            logger.info("🔍 findByUsername natijasi: {}", byUsername.isPresent() ? "TOPILDI" : "TOPILMADI");

            // Email bo'yicha sinash
            Optional<User> byEmail = userRepository.findByEmail(usernameOrEmail);
            logger.info("🔍 findByEmail natijasi: {}", byEmail.isPresent() ? "TOPILDI" : "TOPILMADI");

            if (byUsername.isPresent()) {
                userOpt = byUsername;
                logger.info("✅ Username bo'yicha topildi!");
            } else if (byEmail.isPresent()) {
                userOpt = byEmail;
                logger.info("✅ Email bo'yicha topildi!");
            }
        }

        // 4. Hali ham topilmasa
        if (userOpt.isEmpty()) {
            logger.error("❌ User topilmadi hech qanday usul bilan: '{}'", usernameOrEmail);
            logger.error("❌ Mavjud usernameler:");
            userRepository.findAll().forEach(u ->
                    logger.error("   - '{}'", u.getUsername()));
            throw new UsernameNotFoundException("User not found: " + usernameOrEmail);
        }

        User user = userOpt.get();
        logger.info("✅ User topildi:");
        logger.info("   - ID: {}", user.getId());
        logger.info("   - Username: '{}'", user.getUsername());
        logger.info("   - Email: '{}'", user.getEmail());
        logger.info("   - Password hash: '{}'", user.getPassword());
        logger.info("   - Active: {}", user.isActive());
        logger.info("   - Account locked: {}", user.isAccountLocked());

        // 5. Account holatini tekshirish
        if (!user.isActive()) {
            logger.warn("❌ User account faol emas: {}", user.getUsername());
            throw new UsernameNotFoundException("User account is inactive: " + user.getUsername());
        }

        if (user.isAccountLocked()) {
            logger.warn("❌ User account bloklangan: {}", user.getUsername());
            throw new UsernameNotFoundException("User account is locked: " + user.getUsername());
        }

        // 6. Authorities yaratish
        Collection<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER"));
        logger.info("🔑 Authorities yaratildi: {}", authorities);

        // 7. Spring Security User object yaratish
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword()) // Database dan encoded parol
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(user.isAccountLocked())
                .credentialsExpired(false)
                .disabled(!user.isActive())
                .build();

        logger.info("✅ UserDetails object yaratildi:");
        logger.info("   - Username: '{}'", userDetails.getUsername());
        logger.info("   - Password: '{}'", userDetails.getPassword());
        logger.info("   - Authorities: {}", userDetails.getAuthorities());
        logger.info("   - Enabled: {}", userDetails.isEnabled());
        logger.info("   - Account non locked: {}", userDetails.isAccountNonLocked());
        logger.info("🔍 ==============================================");

        return userDetails;
    }
}