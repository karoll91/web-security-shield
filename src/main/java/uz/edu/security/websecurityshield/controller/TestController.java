package uz.edu.security.websecurityshield.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * ODDIY TEST CONTROLLER - Template va mapping test uchun
 */
@Controller
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * Dashboard - eng oddiy mapping
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        logger.info("🧪 ==============================================");
        logger.info("🧪 TEST DASHBOARD CONTROLLER CALLED");
        logger.info("🧪 ==============================================");

        try {
            // Authentication tekshirish
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            logger.info("✅ Authentication: {}", auth != null ? "EXISTS" : "NULL");

            if (auth != null) {
                logger.info("✅ Username: '{}'", auth.getName());
                logger.info("✅ Authorities: {}", auth.getAuthorities());
                model.addAttribute("username", auth.getName());
                model.addAttribute("authorities", auth.getAuthorities().toString());
            }

            // Simple model attributes
            model.addAttribute("message", "Dashboard Test Muvaffaqiyatli!");
            model.addAttribute("timestamp", java.time.LocalDateTime.now().toString());

            logger.info("✅ Model attributes qo'shildi");
            logger.info("🧪 Returning 'test-dashboard' template");

            return "test-dashboard";

        } catch (Exception e) {
            logger.error("❌ Dashboard test da xatolik: ", e);
            model.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    /**
     * Simple test page - hech qanday dependency yo'q
     */
    @GetMapping("/test")
    public String test(Model model) {
        logger.info("🧪 Simple test page called");
        model.addAttribute("message", "Test sahifasi ishlayapti!");
        return "test";
    }

    /**
     * Direct simple response - template yo'q
     */
    @GetMapping("/simple")
    public String simple() {
        logger.info("🧪 Simple response");
        return "redirect:/test";
    }
}