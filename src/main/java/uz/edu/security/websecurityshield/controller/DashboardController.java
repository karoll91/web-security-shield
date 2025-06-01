package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.service.LoggingService;
import uz.edu.security.websecurityshield.service.SecurityService;
import uz.edu.security.websecurityshield.service.UserService;
import uz.edu.security.websecurityshield.repository.BlockedIPRepository;

import java.time.LocalDateTime;

/**
 * DEBUG VERSION - Dashboard Controller
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private static final Logger logger = LoggerFactory.getLogger(DashboardController.class);

    @Autowired
    private LoggingService loggingService;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private UserService userService;

    @Autowired
    private BlockedIPRepository blockedIPRepository;

    /**
     * Dashboard asosiy sahifasi - DEBUG
     */
    @GetMapping
    public String dashboard(HttpSession session, Model model) {
        logger.info("🏠 ==============================================");
        logger.info("🏠 DASHBOARD CONTROLLER CALLED");
        logger.info("🏠 ==============================================");

        // Authentication context tekshirish
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logger.info("✅ Authentication object: {}", auth != null ? "EXISTS" : "NULL");

        if (auth != null) {
            logger.info("✅ Authentication details:");
            logger.info("   - Principal: {}", auth.getPrincipal().getClass().getSimpleName());
            logger.info("   - Authenticated: {}", auth.isAuthenticated());
            logger.info("   - Authorities: {}", auth.getAuthorities());

            if (auth.getPrincipal() instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) auth.getPrincipal();
                logger.info("   - Username: '{}'", userDetails.getUsername());
            }
        }

        // Session tekshirish
        logger.info("📊 Session ma'lumotlari:");
        logger.info("   - Session ID: {}", session.getId());
        logger.info("   - Session creation time: {}", session.getCreationTime());
        logger.info("   - Session last accessed: {}", session.getLastAccessedTime());

        // Current user olish
        User currentUser = getCurrentUser(session, auth);
        if (currentUser == null) {
            logger.warn("❌ Current user NULL - login ga redirect");
            return "redirect:/login";
        }

        logger.info("✅ Current user: '{}'", currentUser.getUsername());

        try {
            // Model ma'lumotlarini qo'shish
            model.addAttribute("currentUser", currentUser);

            // Dashboard statistikasini olish
            logger.info("📊 Dashboard statistikasini olish...");

            LoggingService.DashboardStats dashboardStats = loggingService.getDashboardStats();
            SecurityService.SecurityStats securityStats = securityService.getSecurityStats();
            UserService.UserStats userStats = userService.getUserStats();

            model.addAttribute("dashboardStats", dashboardStats);
            model.addAttribute("securityStats", securityStats);
            model.addAttribute("userStats", userStats);

            // So'nggi hodisalar
            model.addAttribute("recentLogs", loggingService.getRecentLogs(10));
            model.addAttribute("criticalAttacks", loggingService.getCriticalAttacks(1));
            model.addAttribute("topAttackingIPs", loggingService.getTopAttackingIPs(7, 5));

            // Hujum turlari statistikasi
            model.addAttribute("threatTypeStats", loggingService.getThreatTypeStatistics(7));

            // Kunlik statistika (so'nggi 7 kun)
            model.addAttribute("dailyStats", loggingService.getDailyAttackStatistics(7));

            // Faol bloklangan IP lar soni
            long activeBlocks = blockedIPRepository.countActiveBlocks(LocalDateTime.now());
            model.addAttribute("activeBlocks", activeBlocks);

            logger.info("✅ Model ma'lumotlari qo'shildi");
            logger.info("🏠 ==============================================");
            logger.info("🏠 DASHBOARD TEMPLATE 'dashboard' GA REDIRECT");
            logger.info("🏠 ==============================================");

            return "dashboard";

        } catch (Exception e) {
            logger.error("❌ Dashboard da xatolik: ", e);
            model.addAttribute("errorMessage", "Dashboard yuklanmadi: " + e.getMessage());
            return "error";
        }
    }

    /**
     * Current user olish (session yoki authentication dan)
     */
    private User getCurrentUser(HttpSession session, Authentication auth) {
        logger.info("🔍 Current user ni olish...");

        // Session dan olishga harakat
        User sessionUser = (User) session.getAttribute("currentUser");
        if (sessionUser != null) {
            logger.info("✅ User session dan olindi: '{}'", sessionUser.getUsername());
            return sessionUser;
        }

        // Authentication dan olishga harakat
        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) auth.getPrincipal();
            String username = userDetails.getUsername();
            logger.info("🔍 Authentication dan username: '{}'", username);

            // Database dan user olish
            return userService.findByUsername(username).orElse(null);
        }

        logger.warn("❌ Current user topilmadi");
        return null;
    }

    /**
     * Test mapping - oddiy sahifa
     */
    @GetMapping("/test")
    public String test(Model model) {
        logger.info("🧪 Dashboard test sahifasi chaqirildi");
        model.addAttribute("message", "Dashboard controller ishlayapti!");
        return "dashboard"; // dashboard.html ni render qiladi
    }
}