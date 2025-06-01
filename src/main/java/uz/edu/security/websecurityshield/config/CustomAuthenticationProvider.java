package uz.edu.security.websecurityshield.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Custom Authentication Provider - Constructor injection bilan
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    // Constructor injection
    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        logger.info("🔐 ==============================================");
        logger.info("🔐 CUSTOM AUTHENTICATION PROVIDER");
        logger.info("🔐 Username: '{}'", username);
        logger.info("🔐 Password length: {}", password.length());
        logger.info("🔐 Password first 3 chars: {}", password.length() >= 3 ? password.substring(0, 3) + "..." : password);
        logger.info("🔐 ==============================================");

        try {
            // UserDetailsService dan user olish
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            logger.info("✅ UserDetails loaded successfully");
            logger.info("   - Username: '{}'", userDetails.getUsername());
            logger.info("   - Password from DB: '{}'", userDetails.getPassword());
            logger.info("   - Enabled: {}", userDetails.isEnabled());
            logger.info("   - Account non locked: {}", userDetails.isAccountNonLocked());

            // Password tekshirish
            logger.info("🔑 Password verification:");
            logger.info("   - Raw password: '{}'", password);
            logger.info("   - Encoded password: '{}'", userDetails.getPassword());

            boolean passwordMatch = passwordEncoder.matches(password, userDetails.getPassword());
            logger.info("   - Password matches: {}", passwordMatch);

            if (!passwordMatch) {
                // Qo'shimcha debug
                logger.error("❌ PASSWORD MISMATCH DEBUG:");
                logger.error("   - Raw password bytes: {}", password.getBytes().length);
                logger.error("   - Raw password trim: '{}'", password.trim());
                logger.error("   - Encoded password length: {}", userDetails.getPassword().length());

                // Test encoding
                String testEncoded = passwordEncoder.encode(password);
                logger.error("   - Test encoding same password: '{}'", testEncoded);
                logger.error("   - Test encoding matches: {}", passwordEncoder.matches(password, testEncoded));

                throw new BadCredentialsException("Password does not match");
            }

            // Account status tekshirish
            if (!userDetails.isEnabled()) {
                logger.error("❌ Account is disabled");
                throw new BadCredentialsException("Account is disabled");
            }

            if (!userDetails.isAccountNonLocked()) {
                logger.error("❌ Account is locked");
                throw new BadCredentialsException("Account is locked");
            }

            // Muvaffaqiyatli authentication
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                    userDetails, password, userDetails.getAuthorities());

            logger.info("✅ ==============================================");
            logger.info("✅ AUTHENTICATION SUCCESSFUL");
            logger.info("✅ User: '{}' authenticated successfully", username);
            logger.info("✅ Authorities: {}", userDetails.getAuthorities());
            logger.info("✅ ==============================================");

            return result;

        } catch (Exception e) {
            logger.error("❌ ==============================================");
            logger.error("❌ AUTHENTICATION FAILED");
            logger.error("❌ Username: '{}'", username);
            logger.error("❌ Error: {}", e.getMessage());
            logger.error("❌ ==============================================", e);
            throw new BadCredentialsException("Authentication failed: " + e.getMessage());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}