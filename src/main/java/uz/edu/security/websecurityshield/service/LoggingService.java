package uz.edu.security.websecurityshield.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import uz.edu.security.websecurityshield.entity.SecurityLog;
import uz.edu.security.websecurityshield.repository.SecurityLogRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Logging va monitoring operatsiyalari uchun servis
 */
@Service
public class LoggingService {

    @Autowired
    private SecurityLogRepository securityLogRepository;

    /**
     * Barcha loglarni olish
     */
    public List<SecurityLog> getAllLogs() {
        return securityLogRepository.findAll();
    }

    /**
     * So'nggi loglarni olish
     */
    public List<SecurityLog> getRecentLogs(int limit) {
        if (limit <= 10) {
            return securityLogRepository.findTop10ByOrderByTimestampDesc();
        } else {
            return securityLogRepository.findTop50ByOrderByTimestampDesc();
        }
    }

    /**
     * Bugungi loglarni olish
     */
    public List<SecurityLog> getTodayLogs() {
        LocalDateTime startOfDay = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0);
        return securityLogRepository.findTodayLogs(startOfDay);
    }

    /**
     * Kritik hujumlarni olish
     */
    public List<SecurityLog> getCriticalAttacks(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<SecurityLog.Severity> criticalSeverities = List.of(
                SecurityLog.Severity.HIGH,
                SecurityLog.Severity.CRITICAL
        );
        return securityLogRepository.findBySeverityInAndTimestampGreaterThanEqualOrderByTimestampDesc(
                criticalSeverities, since);
    }

    /**
     * IP bo'yicha loglarni olish
     */
    public List<SecurityLog> getLogsByIP(String ipAddress) {
        return securityLogRepository.findByIpAddressOrderByTimestampDesc(ipAddress);
    }

    /**
     * Threat type bo'yicha loglarni olish
     */
    public List<SecurityLog> getLogsByThreatType(SecurityLog.ThreatType threatType) {
        return securityLogRepository.findByThreatTypeOrderByTimestampDesc(threatType);
    }

    /**
     * Bloklangan hujumlarni olish
     */
    public List<SecurityLog> getBlockedAttacks() {
        return securityLogRepository.findByBlockedTrueOrderByTimestampDesc();
    }

    /**
     * Hujum turlari statistikasi
     */
    public Map<SecurityLog.ThreatType, Long> getThreatTypeStatistics(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<Object[]> results = securityLogRepository.getThreatTypeStatistics(since);

        return results.stream()
                .collect(Collectors.toMap(
                        row -> (SecurityLog.ThreatType) row[0],
                        row -> (Long) row[1]
                ));
    }

    /**
     * Eng ko'p hujum qiluvchi IP lar
     */
    public List<AttackingIP> getTopAttackingIPs(int days, int limit) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<Object[]> results = securityLogRepository.findTopAttackingIPs(since);

        return results.stream()
                .limit(limit)
                .map(row -> new AttackingIP((String) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    /**
     * Kunlik hujumlar statistikasi
     */
    public List<DailyAttackStat> getDailyAttackStatistics(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<Object[]> results = securityLogRepository.getDailyAttackStatistics(since);

        return results.stream()
                .map(row -> new DailyAttackStat(row[0].toString(), (Long) row[1]))
                .collect(Collectors.toList());
    }

    /**
     * Bloklangan hujumlar foizi
     */
    public double getBlockedAttacksPercentage(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        Double percentage = securityLogRepository.getBlockedAttacksPercentage(since);
        return percentage != null ? percentage : 0.0;
    }

    /**
     * Vaqt oralig'idagi loglar
     */
    public List<SecurityLog> getLogsBetweenDates(LocalDateTime startDate, LocalDateTime endDate) {
        return securityLogRepository.findLogsBetweenDates(startDate, endDate);
    }

    /**
     * Ma'lum IP dan so'nggi hujumlar
     */
    public List<SecurityLog> getRecentAttacksByIP(String ipAddress, int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return securityLogRepository.findRecentAttacksByIP(ipAddress, since);
    }

    /**
     * Dashboard uchun umumiy statistika
     */
    public DashboardStats getDashboardStats() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime dayAgo = now.minusDays(1);
        LocalDateTime weekAgo = now.minusDays(7);
        LocalDateTime monthAgo = now.minusDays(30);

        // Asosiy raqamlar
        long totalAttacks = securityLogRepository.count();
        long todayAttacks = securityLogRepository.findTodayLogs(
                now.withHour(0).withMinute(0).withSecond(0)).size();
        long weeklyAttacks = securityLogRepository.findLogsBetweenDates(weekAgo, now).size();
        long monthlyAttacks = securityLogRepository.findLogsBetweenDates(monthAgo, now).size();

        // Kritik hujumlar
        long criticalAttacks = securityLogRepository.findCriticalAttacks(dayAgo).size();

        // Bloklangan hujumlar foizi
        double blockedPercentage = getBlockedAttacksPercentage(7);

        // Eng ko'p tarqalgan hujum turi
        Map<SecurityLog.ThreatType, Long> threatStats = getThreatTypeStatistics(7);
        SecurityLog.ThreatType mostCommonThreat = threatStats.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);

        // Eng xavfli IP
        List<AttackingIP> topIPs = getTopAttackingIPs(7, 1);
        String mostDangerousIP = !topIPs.isEmpty() ? topIPs.get(0).ipAddress : null;

        return new DashboardStats(
                totalAttacks, todayAttacks, weeklyAttacks, monthlyAttacks,
                criticalAttacks, blockedPercentage, mostCommonThreat, mostDangerousIP
        );
    }

    // Yordamchi klasslar
    public static class AttackingIP {
        public final String ipAddress;
        public final Long attackCount;

        public AttackingIP(String ipAddress, Long attackCount) {
            this.ipAddress = ipAddress;
            this.attackCount = attackCount;
        }
    }

    public static class DailyAttackStat {
        public final String date;
        public final Long attackCount;

        public DailyAttackStat(String date, Long attackCount) {
            this.date = date;
            this.attackCount = attackCount;
        }
    }

    public static class DashboardStats {
        public final long totalAttacks;
        public final long todayAttacks;
        public final long weeklyAttacks;
        public final long monthlyAttacks;
        public final long criticalAttacks;
        public final double blockedPercentage;
        public final SecurityLog.ThreatType mostCommonThreat;
        public final String mostDangerousIP;

        public DashboardStats(long totalAttacks, long todayAttacks, long weeklyAttacks,
                              long monthlyAttacks, long criticalAttacks, double blockedPercentage,
                              SecurityLog.ThreatType mostCommonThreat, String mostDangerousIP) {
            this.totalAttacks = totalAttacks;
            this.todayAttacks = todayAttacks;
            this.weeklyAttacks = weeklyAttacks;
            this.monthlyAttacks = monthlyAttacks;
            this.criticalAttacks = criticalAttacks;
            this.blockedPercentage = blockedPercentage;
            this.mostCommonThreat = mostCommonThreat;
            this.mostDangerousIP = mostDangerousIP;
        }
    }
}