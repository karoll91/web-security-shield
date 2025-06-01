package uz.edu.security.websecurityshield;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Web Security Shield - Bitiruv malakaviy ishi
 *
 * Mavzu: "Web saytlarga bo'ladigan hujumlarda axborot xavfsizligini
 * ta'minlovchi himoya mexanizmlarini ishlab chiqish"
 *
 * Mualliflar: [Sizning ismingiz]
 * Universitet: [Universitet nomi]
 * Yil: 2025
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class WebSecurityShieldApplication {

    public static void main(String[] args) {
        System.out.println("=================================");
        System.out.println("🛡️  WEB SECURITY SHIELD 🛡️");
        System.out.println("=================================");
        System.out.println("Web saytlar xavfsizlik tizimi ishga tushmoqda...");
        System.out.println("Port: 8080");
        System.out.println("Dashboard: http://localhost:8080");
        System.out.println("H2 Database: http://localhost:8080/h2-console");
        System.out.println("=================================");

        SpringApplication.run(WebSecurityShieldApplication.class, args);

        System.out.println("✅ Tizim muvaffaqiyatli ishga tushdi!");
    }
}
