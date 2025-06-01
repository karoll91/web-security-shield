package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
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
 * Asosiy Dashboard Controller
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    @Autowired
    private LoggingService loggingService;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private UserService userService;

    @Autowired
    private BlockedIPRepository blockedIPRepository;

    /**
     * Dashboard asosiy sahifasi
     */
    @GetMapping
    public String dashboard(HttpSession session, Model model) {
        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        // Dashboard statistikasini olish
        LoggingService.DashboardStats dashboardStats = loggingService.getDashboardStats();
        SecurityService.SecurityStats securityStats = securityService.getSecurityStats();
        UserService.UserStats userStats = userService.getUserStats();

        // Model ga ma'lumotlar qo'shish
        model.addAttribute("currentUser", currentUser);
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

        return "dashboard";
    }

    /**
     * Haqida sahifasi
     */
    @GetMapping("/about")
    public String about(HttpSession session, Model model) {
        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        model.addAttribute("currentUser", currentUser);

        // Tizim ma'lumotlari
        model.addAttribute("systemInfo", new SystemInfo());

        return "about";
    }

    /**
     * Profil sahifasi
     */
    @GetMapping("/profile")
    public String profile(HttpSession session, Model model) {
        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        model.addAttribute("currentUser", currentUser);

        // Foydalanuvchi statistikasi
        model.addAttribute("userStats", userService.getUserStats());

        return "profile";
    }

    /**
     * Yordam sahifasi
     */
    @GetMapping("/help")
    public String help(HttpSession session, Model model) {
        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        model.addAttribute("currentUser", currentUser);
        return "help";
    }

    /**
     * Session dan joriy foydalanuvchini olish
     */
    private User getCurrentUser(HttpSession session) {
        return (User) session.getAttribute("currentUser");
    }

    /**
     * Tizim ma'lumotlari klassi
     */
    public static class SystemInfo {
        public final String projectName = "Web Security Shield";
        public final String version = "1.0.0";
        public final String description = "Web saytlarga bo'ladigan hujumlarga qarshi himoya tizimi";
        public final String author = "Bitiruv malakaviy ishi";
        public final String university = "[Universitet nomi]";
        public final String year = "2025";
        public final String[] features = {
                "XSS (Cross-Site Scripting) hujumlaridan himoya",
                "SQL Injection hujumlaridan himoya",
                "Rate Limiting (so'rovlar cheklash)",
                "IP Address bloklash",
                "Real-time monitoring va logging",
                "Xavfsizlik hodisalari statistikasi",
                "Avtomatik threat detection",
                "Dashboard va reporting"
        };
        public final String[] technologies = {
                "Java 17",
                "Spring Boot 3.2.0",
                "Spring Security",
                "Spring Data JPA",
                "Thymeleaf",
                "H2 Database",
                "Gradle",
                "Bootstrap 5"
        };
    }
}