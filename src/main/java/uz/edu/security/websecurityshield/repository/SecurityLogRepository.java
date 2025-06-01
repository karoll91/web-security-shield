package uz.edu.security.websecurityshield.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import uz.edu.security.websecurityshield.entity.SecurityLog;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Xavfsizlik loglari bilan ishlash uchun Repository
 */
@Repository
public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

    /**
     * IP manzil bo'yicha loglarni topish
     */
    List<SecurityLog> findByIpAddressOrderByTimestampDesc(String ipAddress);

    /**
     * Threat type bo'yicha loglarni topish
     */
    List<SecurityLog> findByThreatTypeOrderByTimestampDesc(SecurityLog.ThreatType threatType);

    /**
     * Xavflilik darajasi bo'yicha loglarni topish
     */
    List<SecurityLog> findBySeverityOrderByTimestampDesc(SecurityLog.Severity severity);

    /**
     * Bloklangan hujumlarni topish
     */
    List<SecurityLog> findByBlockedTrueOrderByTimestampDesc();

    /**
     * Ma'lum vaqt oralig'idagi loglar
     */
    @Query("SELECT s FROM SecurityLog s WHERE s.timestamp BETWEEN :startDate AND :endDate ORDER BY s.timestamp DESC")
    List<SecurityLog> findLogsBetweenDates(@Param("startDate") LocalDateTime startDate,
                                           @Param("endDate") LocalDateTime endDate);

    /**
     * Bugungi loglar
     */
    @Query("SELECT s FROM SecurityLog s WHERE s.timestamp >= :startOfDay ORDER BY s.timestamp DESC")
    List<SecurityLog> findTodayLogs(@Param("startOfDay") LocalDateTime startOfDay);

    /**
     * So'nggi N ta log
     */
    List<SecurityLog> findTop10ByOrderByTimestampDesc();

    List<SecurityLog> findTop50ByOrderByTimestampDesc();

    /**
     * IP manzil bo'yicha hujumlar sonini hisoblash
     */
    @Query("SELECT COUNT(s) FROM SecurityLog s WHERE s.ipAddress = :ipAddress AND s.timestamp >= :since")
    long countAttacksByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    /**
     * Threat type bo'yicha hujumlar sonini hisoblash
     */
    @Query("SELECT COUNT(s) FROM SecurityLog s WHERE s.threatType = :threatType AND s.timestamp >= :since")
    long countAttacksByTypeSince(@Param("threatType") SecurityLog.ThreatType threatType,
                                 @Param("since") LocalDateTime since);

    /**
     * Eng ko'p hujum qilingan IP lar
     */
    @Query("SELECT s.ipAddress, COUNT(s) FROM SecurityLog s " +
            "WHERE s.timestamp >= :since GROUP BY s.ipAddress ORDER BY COUNT(s) DESC")
    List<Object[]> findTopAttackingIPs(@Param("since") LocalDateTime since);

    /**
     * Hujum turlari statistikasi
     */
    @Query("SELECT s.threatType, COUNT(s) FROM SecurityLog s " +
            "WHERE s.timestamp >= :since GROUP BY s.threatType ORDER BY COUNT(s) DESC")
    List<Object[]> getThreatTypeStatistics(@Param("since") LocalDateTime since);

    /**
     * Kunlik hujumlar statistikasi
     */
    @Query("SELECT FUNCTION('DATE', s.timestamp), COUNT(s) FROM SecurityLog s " +
            "WHERE s.timestamp >= :since GROUP BY FUNCTION('DATE', s.timestamp) ORDER BY FUNCTION('DATE', s.timestamp) DESC")
    List<Object[]> getDailyAttackStatistics(@Param("since") LocalDateTime since);

    /**
     * Kritik va yuqori xavfli hujumlar - parameter ishlatish
     */
    @Query("SELECT s FROM SecurityLog s WHERE s.severity IN :severities " +
            "AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityLog> findCriticalAttacks(@Param("since") LocalDateTime since);

    /**
     * Kritik va yuqori xavfli hujumlar - oddiy method
     */
    List<SecurityLog> findBySeverityInAndTimestampGreaterThanEqualOrderByTimestampDesc(
            List<SecurityLog.Severity> severities, LocalDateTime since);

    /**
     * Bloklangan hujumlar foizi
     */
    @Query("SELECT " +
            "CAST((SELECT COUNT(s1) FROM SecurityLog s1 WHERE s1.blocked = true AND s1.timestamp >= :since) AS double) * 100.0 / " +
            "CAST((SELECT COUNT(s2) FROM SecurityLog s2 WHERE s2.timestamp >= :since) AS double)")
    Double getBlockedAttacksPercentage(@Param("since") LocalDateTime since);

    /**
     * Ma'lum IP dan kelgan so'nggi hujumlar
     */
    @Query("SELECT s FROM SecurityLog s WHERE s.ipAddress = :ipAddress " +
            "AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityLog> findRecentAttacksByIP(@Param("ipAddress") String ipAddress,
                                            @Param("since") LocalDateTime since);
}