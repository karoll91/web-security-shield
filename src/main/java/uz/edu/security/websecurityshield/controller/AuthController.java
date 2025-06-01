package uz.edu.security.websecurityshield.controller;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import uz.edu.security.websecurityshield.entity.User;
import uz.edu.security.websecurityshield.service.UserService;

/**
 * Login va Register operatsiyalari uchun Controller - SIMPLIFIED VERSION
 * Spring Security o'zi authentication bilan shug'ullanadi
 */
@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

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
     * LOGIN POST METODINI O'CHIRISH!
     * Spring Security o'zi POST /login ni handle qiladi
     * Bizga kerak emas!
     */

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
     * Bosh sahifa - dashboard ga yo'naltirish
     */
    @GetMapping("/")
    public String home() {
        // Spring Security avtomatik authentication tekshiradi
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            String username = ((UserDetails) principal).getUsername();
            logger.info("🏠 Home: {} dashboard ga yo'naltirildi", username);
            return "redirect:/dashboard";
        } else {
            logger.info("🏠 Home: Login sahifasiga yo'naltirildi");
            return "redirect:/login";
        }
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