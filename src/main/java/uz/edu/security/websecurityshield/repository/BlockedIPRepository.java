package uz.edu.security.websecurityshield.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import uz.edu.security.websecurityshield.entity.BlockedIP;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Bloklangan IP lar bilan ishlash uchun Repository
 */
@Repository
public interface BlockedIPRepository extends JpaRepository<BlockedIP, Long> {

    /**
     * IP manzil bo'yicha bloklangan IP ni topish
     */
    Optional<BlockedIP> findByIpAddress(String ipAddress);

    /**
     * IP manzil bloklanganligini tekshirish
     */
    boolean existsByIpAddress(String ipAddress);

    /**
     * Faol bloklangan IP lar (muddati o'tmagan)
     */
    @Query("SELECT b FROM BlockedIP b WHERE " +
            "(b.permanent = true) OR " +
            "(b.permanent = false AND (b.expiresAt IS NULL OR b.expiresAt > :now))")
    List<BlockedIP> findActiveBlockedIPs(@Param("now") LocalDateTime now);

    /**
     * Muddati o'tgan bloklangan IP lar
     */
    @Query("SELECT b FROM BlockedIP b WHERE " +
            "b.permanent = false AND b.expiresAt IS NOT NULL AND b.expiresAt <= :now")
    List<BlockedIP> findExpiredBlockedIPs(@Param("now") LocalDateTime now);

    /**
     * Doimiy bloklangan IP lar
     */
    List<BlockedIP> findByPermanentTrue();

    /**
     * Vaqtinchalik bloklangan IP lar
     */
    List<BlockedIP> findByPermanentFalse();

    /**
     * Block type bo'yicha bloklangan IP lar
     */
    List<BlockedIP> findByBlockType(BlockedIP.BlockType blockType);

    /**
     * Ma'lum vaqtdan keyin bloklangan IP lar
     */
    List<BlockedIP> findByBlockedAtAfterOrderByBlockedAtDesc(LocalDateTime since);

    /**
     * Ko'p marta bloklangan IP lar
     */
    @Query("SELECT b FROM BlockedIP b WHERE b.blockCount >= :minCount ORDER BY b.blockCount DESC")
    List<BlockedIP> findFrequentlyBlockedIPs(@Param("minCount") int minCount);

    /**
     * IP ning faol bloklanganligini tekshirish
     */
    @Query("SELECT CASE WHEN COUNT(b) > 0 THEN true ELSE false END FROM BlockedIP b WHERE " +
            "b.ipAddress = :ipAddress AND " +
            "((b.permanent = true) OR " +
            "(b.permanent = false AND (b.expiresAt IS NULL OR b.expiresAt > :now)))")
    boolean isIpActivelyBlocked(@Param("ipAddress") String ipAddress, @Param("now") LocalDateTime now);

    /**
     * Muddati o'tgan bloklarni o'chirish
     */
    @Modifying
    @Query("DELETE FROM BlockedIP b WHERE " +
            "b.permanent = false AND b.expiresAt IS NOT NULL AND b.expiresAt <= :now")
    int deleteExpiredBlocks(@Param("now") LocalDateTime now);

    /**
     * Bloklangan IP lar statistikasi
     */
    @Query("SELECT b.blockType, COUNT(b) FROM BlockedIP b GROUP BY b.blockType")
    List<Object[]> getBlockTypeStatistics();

    /**
     * Bugungi bloklangan IP lar soni
     */
    @Query("SELECT COUNT(b) FROM BlockedIP b WHERE b.blockedAt >= :startOfDay")
    long countTodayBlockedIPs(@Param("startOfDay") LocalDateTime startOfDay);

    /**
     * Jami faol bloklangan IP lar soni
     */
    @Query("SELECT COUNT(b) FROM BlockedIP b WHERE " +
            "(b.permanent = true) OR " +
            "(b.permanent = false AND (b.expiresAt IS NULL OR b.expiresAt > :now))")
    long countActiveBlocks(@Param("now") LocalDateTime now);

    /**
     * So'nggi faoliyat bo'yicha bloklangan IP lar
     */
    List<BlockedIP> findTop20ByOrderByLastAttemptDesc();

    /**
     * Ma'lum muddat ichida faol bo'lgan bloklangan IP lar
     */
    @Query("SELECT b FROM BlockedIP b WHERE b.lastAttempt >= :since ORDER BY b.lastAttempt DESC")
    List<BlockedIP> findRecentlyActiveBlocks(@Param("since") LocalDateTime since);
}