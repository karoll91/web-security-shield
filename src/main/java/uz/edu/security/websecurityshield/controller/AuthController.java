package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.service.SecurityService;
import uz.edu.security.websecurityshield.service.UserService;

/**
 * Login va Register operatsiyalari uchun Controller - DEBUG VERSION
 */
@Controller
public class AuthController {

    // Logger qo'shish
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private SecurityService securityService;

    /**
     * Login sahifasini ko'rsatish
     */
    @GetMapping("/login")
    public String showLoginPage(Model model,
                                @RequestParam(value = "error", required = false) String error,
                                @RequestParam(value = "logout", required = false) String logout) {

        logger.info("🎯 Login sahifasi so'raldi. Error: {}, Logout: {}", error, logout);

        if (error != null) {
            model.addAttribute("errorMessage", "Noto'g'ri login yoki parol!");
            logger.warn("❌ Login sahifasida error ko'rsatildi");
        }

        if (logout != null) {
            model.addAttribute("successMessage", "Muvaffaqiyatli chiqildi!");
            logger.info("✅ Logout muvaffaqiyatli");
        }

        model.addAttribute("loginForm", new LoginForm());
        return "login";
    }

    /**
     * Login jarayonini qayta ishlash - DEBUG VERSION
     */
    @PostMapping("/login")
    public String processLogin(@Valid @ModelAttribute("loginForm") LoginForm loginForm,
                               BindingResult bindingResult,
                               HttpServletRequest request,
                               HttpSession session,
                               RedirectAttributes redirectAttributes) {

        // DEBUG - BOSHLANISH
        logger.info("🚀 =================================");
        logger.info("🚀 LOGIN JARAYONI BOSHLANDI");
        logger.info("🚀 =================================");

        // Login ma'lumotlarini log qilish
        logger.info("🔑 Login urinishi - Username: {}", loginForm.getLogin());
        logger.info("🔑 Password uzunligi: {}", loginForm.getPassword() != null ? loginForm.getPassword().length() : "NULL");
        logger.info("🔑 Password (birinchi 3 ta harf): {}",
                loginForm.getPassword() != null && loginForm.getPassword().length() >= 3 ?
                        loginForm.getPassword().substring(0, 3) + "..." : "NULL");

        // Validation tekshirish
        if (bindingResult.hasErrors()) {
            logger.warn("❌ Form validation errors: {}", bindingResult.getAllErrors());
            return "login";
        }

        // IP Address olish
        String ipAddress = getClientIpAddress(request);
        logger.info("📍 Client IP Address: {}", ipAddress);

        // IP bloklanganligini tekshirish
        try {
            if (securityService.isIPBlocked(ipAddress)) {
                logger.warn("🚫 IP bloklangan: {}", ipAddress);
                redirectAttributes.addFlashAttribute("errorMessage",
                        "Sizning IP manzilingiz bloklangan. Keyinroq urinib ko'ring.");
                return "redirect:/login?error=blocked";
            }
            logger.info("✅ IP bloklanmagan: {}", ipAddress);
        } catch (Exception e) {
            logger.error("❌ IP bloklanganligini tekshirishda xatolik: ", e);
        }

        // Rate limit tekshirish
        try {
            if (!securityService.checkRateLimit(ipAddress)) {
                logger.warn("⏰ Rate limit oshdi: {}", ipAddress);
                securityService.handleSecurityThreat(
                        uz.edu.security.websecurityshield.entity.SecurityLog.ThreatType.RATE_LIMIT_EXCEEDED,
                        ipAddress, "/login", "Rate limit exceeded");

                redirectAttributes.addFlashAttribute("errorMessage",
                        "Juda ko'p urinish. Keyinroq qaytadan urining.");
                return "redirect:/login?error=ratelimit";
            }
            logger.info("✅ Rate limit OK: {}", ipAddress);
        } catch (Exception e) {
            logger.error("❌ Rate limit tekshirishda xatolik: ", e);
        }

        // Foydalanuvchini autentifikatsiya qilish
        logger.info("🔍 =================================");
        logger.info("🔍 AUTENTIFIKATSIYA BOSHLANDI");
        logger.info("🔍 =================================");

        UserService.LoginResult result = null;
        try {
            result = userService.authenticateUser(
                    loginForm.getLogin(), loginForm.getPassword(), ipAddress);

            logger.info("🎯 Autentifikatsiya tugadi");
            logger.info("🎯 Login natijasi - Success: {}", result != null ? result.isSuccess() : "NULL");
            logger.info("🎯 Login xabari: {}", result != null ? result.getMessage() : "NULL");

        } catch (Exception e) {
            logger.error("❌ Autentifikatsiyada xatolik: ", e);
            redirectAttributes.addFlashAttribute("errorMessage", "Tizimda xatolik yuz berdi");
            return "redirect:/login?error=system";
        }

        // Natijani qayta ishlash
        if (result != null && result.isSuccess()) {
            // Session yaratish
            session.setAttribute("currentUser", result.getUser());
            session.setAttribute("loginTime", System.currentTimeMillis());

            logger.info("✅ =================================");
            logger.info("✅ MUVAFFAQIYATLI LOGIN: {}", result.getUser().getUsername());
            logger.info("✅ =================================");

            redirectAttributes.addFlashAttribute("successMessage",
                    "Xush kelibsiz, " + result.getUser().getUsername() + "!");
            return "redirect:/dashboard";
        } else {
            String errorMsg = result != null ? result.getMessage() : "Noma'lum xatolik";
            logger.warn("❌ =================================");
            logger.warn("❌ LOGIN MUVAFFAQIYATSIZ: {}", errorMsg);
            logger.warn("❌ =================================");

            redirectAttributes.addFlashAttribute("errorMessage", errorMsg);
            return "redirect:/login?error=credentials";
        }
    }

    /**
     * Register sahifasini ko'rsatish
     */
    @GetMapping("/register")
    public String showRegisterPage(Model model) {
        logger.info("📝 Register sahifasi so'raldi");
        model.addAttribute("registerForm", new RegisterForm());
        return "register";
    }

    /**
     * Register jarayonini qayta ishlash
     */
    @PostMapping("/register")
    public String processRegister(@Valid @ModelAttribute("registerForm") RegisterForm registerForm,
                                  BindingResult bindingResult,
                                  HttpServletRequest request,
                                  RedirectAttributes redirectAttributes) {

        logger.info("📝 Register urinishi - Username: {}, Email: {}",
                registerForm.getUsername(), registerForm.getEmail());

        if (bindingResult.hasErrors()) {
            logger.warn("❌ Register form validation errors");
            return "register";
        }

        // Parollarni tekshirish
        if (!registerForm.getPassword().equals(registerForm.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch",
                    "Parollar mos kelmaydi");
            logger.warn("❌ Parollar mos kelmadi");
            return "register";
        }

        String ipAddress = getClientIpAddress(request);

        try {
            // Yangi foydalanuvchini ro'yxatdan o'tkazish
            User newUser = userService.registerUser(
                    registerForm.getUsername(),
                    registerForm.getEmail(),
                    registerForm.getPassword()
            );

            logger.info("✅ Yangi foydalanuvchi ro'yxatdan o'tdi: {}", newUser.getUsername());
            redirectAttributes.addFlashAttribute("successMessage",
                    "Muvaffaqiyatli ro'yxatdan o'tdingiz! Endi login qilishingiz mumkin.");
            return "redirect:/login?registered=true";

        } catch (RuntimeException e) {
            logger.error("❌ Ro'yxatdan o'tishda xatolik: {}", e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/register?error=exists";
        }
    }

    /**
     * Logout jarayoni
     */
    @GetMapping("/logout")
    public String logout(HttpSession session, RedirectAttributes redirectAttributes) {
        User currentUser = (User) session.getAttribute("currentUser");
        String username = currentUser != null ? currentUser.getUsername() : "Unknown";

        session.invalidate();
        logger.info("👋 Foydalanuvchi chiqdi: {}", username);
        redirectAttributes.addFlashAttribute("successMessage", "Muvaffaqiyatli chiqildi!");
        return "redirect:/login?logout=true";
    }

    /**
     * Bosh sahifa - dashboard ga yo'naltirish
     */
    @GetMapping("/")
    public String home(HttpSession session) {
        User currentUser = (User) session.getAttribute("currentUser");
        if (currentUser != null) {
            logger.info("🏠 Home: {} dashboard ga yo'naltirildi", currentUser.getUsername());
            return "redirect:/dashboard";
        } else {
            logger.info("🏠 Home: Login sahifasiga yo'naltirildi");
            return "redirect:/login";
        }
    }

    /**
     * Client IP manzilini olish
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String ip = xForwardedFor.split(",")[0].trim();
            logger.debug("📍 IP from X-Forwarded-For: {}", ip);
            return ip;
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            logger.debug("📍 IP from X-Real-IP: {}", xRealIp);
            return xRealIp;
        }

        String remoteAddr = request.getRemoteAddr();
        logger.debug("📍 IP from RemoteAddr: {}", remoteAddr);
        return remoteAddr;
    }

    // Form klasslari
    public static class LoginForm {
        private String login;
        private String password;

        // Getter va Setter
        public String getLogin() { return login; }
        public void setLogin(String login) { this.login = login; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class RegisterForm {
        private String username;
        private String email;
        private String password;
        private String confirmPassword;

        // Getter va Setter
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        public String getConfirmPassword() { return confirmPassword; }
        public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
    }
}