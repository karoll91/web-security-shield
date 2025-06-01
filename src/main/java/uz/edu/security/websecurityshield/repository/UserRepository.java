package uz.edu.security.websecurityshield.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import uz.edu.security.websecurityshield.entity.User;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Foydalanuvchi ma'lumotlari bilan ishlash uchun Repository
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Username bo'yicha foydalanuvchi topish
     */
    Optional<User> findByUsername(String username);

    /**
     * Email bo'yicha foydalanuvchi topish
     */
    Optional<User> findByEmail(String email);

    /**
     * Username yoki email bo'yicha foydalanuvchi topish
     */
    @Query("SELECT u FROM User u WHERE u.username = :login OR u.email = :login")
    Optional<User> findByUsernameOrEmail(@Param("login") String login);

    /**
     * Faol foydalanuvchilarni topish
     */
    List<User> findByActiveTrue();

    /**
     * Bloklangan foydalanuvchilarni topish
     */
    List<User> findByAccountLockedTrue();

    /**
     * Muddati o'tgan bloklangan foydalanuvchilarni topish
     */
    @Query("SELECT u FROM User u WHERE u.accountLocked = true AND u.lockTime < :expireTime")
    List<User> findExpiredLockedUsers(@Param("expireTime") LocalDateTime expireTime);

    /**
     * So'nggi faol foydalanuvchilar
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin > :since ORDER BY u.lastLogin DESC")
    List<User> findRecentActiveUsers(@Param("since") LocalDateTime since);

    /**
     * Ko'p marta noto'g'ri parol kiritgan foydalanuvchilar
     */
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= :maxAttempts AND u.accountLocked = false")
    List<User> findUsersWithHighFailedAttempts(@Param("maxAttempts") int maxAttempts);

    /**
     * Username mavjudligini tekshirish
     */
    boolean existsByUsername(String username);

    /**
     * Email mavjudligini tekshirish
     */
    boolean existsByEmail(String email);

    /**
     * Foydalanuvchilar sonini olish
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.active = true")
    long countActiveUsers();

    /**
     * Bugun ro'yxatdan o'tgan foydalanuvchilar
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :startDate")
    long countUsersRegisteredSince(@Param("startDate") LocalDateTime startDate);
}
