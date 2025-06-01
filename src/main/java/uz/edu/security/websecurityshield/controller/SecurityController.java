package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import uz.edu.security.websecurityshield.entity.BlockedIP;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.repository.BlockedIPRepository;
import uz.edu.security.websecurityshield.service.LoggingService;
import uz.edu.security.websecurityshield.service.SecurityService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Xavfsizlik monitoring va boshqaruv uchun Controller
 */
@Controller
@RequestMapping("/security")
public class SecurityController {

    @Autowired
    private LoggingService loggingService;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private BlockedIPRepository blockedIPRepository;

    /**
     * Xavfsizlik loglarini ko'rsatish
     */
    @GetMapping("/logs")
    public String securityLogs(HttpSession session, Model model,
                               @RequestParam(value = "type", required = false) String threatType,
                               @RequestParam(value = "ip", required = false) String ipAddress,
                               @RequestParam(value = "days", defaultValue = "7") int days) {

        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        List<SecurityLog> logs;

        // Filter bo'yicha loglarni olish
        if (threatType != null && !threatType.isEmpty()) {
            SecurityLog.ThreatType type = SecurityLog.ThreatType.valueOf(threatType);
            logs = loggingService.getLogsByThreatType(type);
        } else if (ipAddress != null && !ipAddress.isEmpty()) {
            logs = loggingService.getLogsByIP(ipAddress);
        } else {
            // So'nggi N kunlik loglar
            LocalDateTime since = LocalDateTime.now().minusDays(days);
            logs = loggingService.getLogsBetweenDates(since, LocalDateTime.now());
        }

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("logs", logs);
        model.addAttribute("threatTypes", SecurityLog.ThreatType.values());
        model.addAttribute("selectedType", threatType);
        model.addAttribute("selectedIP", ipAddress);
        model.addAttribute("selectedDays", days);

        // Statistika
        model.addAttribute("threatTypeStats", loggingService.getThreatTypeStatistics(days));
        model.addAttribute("topAttackingIPs", loggingService.getTopAttackingIPs(days, 10));

        return "security-logs";
    }

    /**
     * Bloklangan IP larni ko'rsatish
     */
    @GetMapping("/blocked-ips")
    public String blockedIPs(HttpSession session, Model model,
                             @RequestParam(value = "type", required = false) String blockType) {

        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        List<BlockedIP> blockedIPs;

        // Filter bo'yicha IP larni olish
        if (blockType != null && !blockType.isEmpty()) {
            BlockedIP.BlockType type = BlockedIP.BlockType.valueOf(blockType);
            blockedIPs = blockedIPRepository.findByBlockType(type);
        } else {
            blockedIPs = blockedIPRepository.findActiveBlockedIPs(LocalDateTime.now());
        }

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("blockedIPs", blockedIPs);
        model.addAttribute("blockTypes", BlockedIP.BlockType.values());
        model.addAttribute("selectedType", blockType);

        // Statistika
        model.addAttribute("blockTypeStats", blockedIPRepository.getBlockTypeStatistics());
        model.addAttribute("totalActiveBlocks", blockedIPRepository.countActiveBlocks(LocalDateTime.now()));
        model.addAttribute("todayBlocks", blockedIPRepository.countTodayBlockedIPs(
                LocalDateTime.now().withHour(0).withMinute(0).withSecond(0)));

        return "blocked-ips";
    }

    /**
     * IP ni qo'lda bloklash
     */
    @PostMapping("/block-ip")
    public String blockIP(@RequestParam("ipAddress") String ipAddress,
                          @RequestParam("reason") String reason,
                          @RequestParam(value = "permanent", defaultValue = "false") boolean permanent,
                          RedirectAttributes redirectAttributes) {

        try {
            if (permanent) {
                BlockedIP block = new BlockedIP(ipAddress, reason, BlockedIP.BlockType.MANUAL);
                block.setPermanent(true);
                blockedIPRepository.save(block);
            } else {
                securityService.blockIP(ipAddress, reason, BlockedIP.BlockType.MANUAL);
            }

            redirectAttributes.addFlashAttribute("successMessage",
                    "IP muvaffaqiyatli bloklandi: " + ipAddress);

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "IP bloklashda xatolik: " + e.getMessage());
        }

        return "redirect:/security/blocked-ips";
    }

    /**
     * IP blokdan chiqarish
     */
    @PostMapping("/unblock-ip/{id}")
    public String unblockIP(@PathVariable Long id, RedirectAttributes redirectAttributes) {

        try {
            Optional<BlockedIP> blockedIP = blockedIPRepository.findById(id);
            if (blockedIP.isPresent()) {
                String ipAddress = blockedIP.get().getIpAddress();
                blockedIPRepository.deleteById(id);
                redirectAttributes.addFlashAttribute("successMessage",
                        "IP blokdan chiqarildi: " + ipAddress);
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "IP topilmadi");
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "IP blokdan chiqarishda xatolik: " + e.getMessage());
        }

        return "redirect:/security/blocked-ips";
    }

    /**
     * Kritik hujumlar
     */
    @GetMapping("/critical-attacks")
    public String criticalAttacks(HttpSession session, Model model,
                                  @RequestParam(value = "days", defaultValue = "1") int days) {

        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        List<SecurityLog> criticalAttacks = loggingService.getCriticalAttacks(days);

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("criticalAttacks", criticalAttacks);
        model.addAttribute("selectedDays", days);

        return "critical-attacks";
    }

    /**
     * Real-time monitoring (AJAX uchun)
     */
    @GetMapping("/live-stats")
    @ResponseBody
    public LiveStats getLiveStats() {
        LoggingService.DashboardStats stats = loggingService.getDashboardStats();
        long activeBlocks = blockedIPRepository.countActiveBlocks(LocalDateTime.now());

        return new LiveStats(
                stats.todayAttacks,
                stats.criticalAttacks,
                activeBlocks,
                stats.blockedPercentage
        );
    }

    /**
     * IP haqida batafsil ma'lumot
     */
    @GetMapping("/ip-details/{ipAddress}")
    public String ipDetails(@PathVariable String ipAddress, HttpSession session, Model model) {

        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        // IP ning barcha loglari
        List<SecurityLog> ipLogs = loggingService.getLogsByIP(ipAddress);

        // IP bloklangan yoki yo'qligi
        Optional<BlockedIP> blockedIP = blockedIPRepository.findByIpAddress(ipAddress);

        // So'nggi 24 soatdagi faoliyat
        List<SecurityLog> recentActivity = loggingService.getRecentAttacksByIP(ipAddress, 24);

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("ipAddress", ipAddress);
        model.addAttribute("ipLogs", ipLogs);
        model.addAttribute("blockedIP", blockedIP.orElse(null));
        model.addAttribute("recentActivity", recentActivity);
        model.addAttribute("isBlocked", securityService.isIPBlocked(ipAddress));

        return "ip-details";
    }

    /**
     * Xavfsizlik sozlamalari
     */
    @GetMapping("/settings")
    public String securitySettings(HttpSession session, Model model) {

        User currentUser = getCurrentUser(session);
        if (currentUser == null) {
            return "redirect:/login";
        }

        model.addAttribute("currentUser", currentUser);

        return "security-settings";
    }

    /**
     * Session dan joriy foydalanuvchini olish
     */
    private User getCurrentUser(HttpSession session) {
        return (User) session.getAttribute("currentUser");
    }

    /**
     * Live statistika klassi
     */
    public static class LiveStats {
        public final long todayAttacks;
        public final long criticalAttacks;
        public final long activeBlocks;
        public final double blockedPercentage;

        public LiveStats(long todayAttacks, long criticalAttacks,
                         long activeBlocks, double blockedPercentage) {
            this.todayAttacks = todayAttacks;
            this.criticalAttacks = criticalAttacks;
            this.activeBlocks = activeBlocks;
            this.blockedPercentage = blockedPercentage;
        }
    }
}
