package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
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
 * Login va Register operatsiyalari uchun Controller
 */
@Controller
public class AuthController {

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

        if (error != null) {
            model.addAttribute("errorMessage", "Noto'g'ri login yoki parol!");
        }

        if (logout != null) {
            model.addAttribute("successMessage", "Muvaffaqiyatli chiqildi!");
        }

        model.addAttribute("loginForm", new LoginForm());
        return "login";
    }

    /**
     * Login jarayonini qayta ishlash
     */
    @PostMapping("/login")
    public String processLogin(@Valid @ModelAttribute("loginForm") LoginForm loginForm,
                               BindingResult bindingResult,
                               HttpServletRequest request,
                               HttpSession session,
                               RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            return "login";
        }

        String ipAddress = getClientIpAddress(request);

        // IP bloklanganligini tekshirish
        if (securityService.isIPBlocked(ipAddress)) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Sizning IP manzilingiz bloklangan. Keyinroq urinib ko'ring.");
            return "redirect:/login?error=blocked";
        }

        // Rate limit tekshirish
        if (!securityService.checkRateLimit(ipAddress)) {
            securityService.handleSecurityThreat(
                    uz.edu.security.websecurityshield.entity.SecurityLog.ThreatType.RATE_LIMIT_EXCEEDED,
                    ipAddress, "/login", "Rate limit exceeded");

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Juda ko'p urinish. Keyinroq qaytadan urining.");
            return "redirect:/login?error=ratelimit";
        }

        // Foydalanuvchini autentifikatsiya qilish
        UserService.LoginResult result = userService.authenticateUser(
                loginForm.getLogin(), loginForm.getPassword(), ipAddress);

        if (result.isSuccess()) {
            // Session yaratish
            session.setAttribute("currentUser", result.getUser());
            session.setAttribute("loginTime", System.currentTimeMillis());

            redirectAttributes.addFlashAttribute("successMessage",
                    "Xush kelibsiz, " + result.getUser().getUsername() + "!");
            return "redirect:/dashboard";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", result.getMessage());
            return "redirect:/login?error=credentials";
        }
    }

    /**
     * Register sahifasini ko'rsatish
     */
    @GetMapping("/register")
    public String showRegisterPage(Model model) {
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

        if (bindingResult.hasErrors()) {
            return "register";
        }

        // Parollarni tekshirish
        if (!registerForm.getPassword().equals(registerForm.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch",
                    "Parollar mos kelmaydi");
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

            redirectAttributes.addFlashAttribute("successMessage",
                    "Muvaffaqiyatli ro'yxatdan o'tdingiz! Endi login qilishingiz mumkin.");
            return "redirect:/login?registered=true";

        } catch (RuntimeException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/register?error=exists";
        }
    }

    /**
     * Logout jarayoni
     */
    @GetMapping("/logout")
    public String logout(HttpSession session, RedirectAttributes redirectAttributes) {
        session.invalidate();
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
            return "redirect:/dashboard";
        } else {
            return "redirect:/login";
        }
    }

    /**
     * Client IP manzilini olish
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
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