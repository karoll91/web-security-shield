package uz.edu.security.websecurityshield.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Xavfsizlik hodisalarini saqlash uchun Entity
 */
@Entity
@Table(name = "security_logs")
public class SecurityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_type", nullable = false)
    private ThreatType threatType;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "request_url")
    private String requestUrl;

    @Column(name = "request_method")
    private String requestMethod;

    @Column(name = "attack_payload", columnDefinition = "TEXT")
    private String attackPayload;

    @Column(name = "blocked")
    private boolean blocked = false;

    @Column(name = "severity")
    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "description")
    private String description;

    // Enum sinflar
    public enum ThreatType {
        XSS_ATTACK("Cross-Site Scripting"),
        SQL_INJECTION("SQL Injection"),
        RATE_LIMIT_EXCEEDED("Rate Limit Exceeded"),
        SUSPICIOUS_REQUEST("Suspicious Request"),
        FAILED_LOGIN("Failed Login Attempt"),
        BRUTE_FORCE("Brute Force Attack");

        private final String displayName;

        ThreatType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    public enum Severity {
        LOW("Past"),
        MEDIUM("O'rtacha"),
        HIGH("Yuqori"),
        CRITICAL("Kritik");

        private final String displayName;

        Severity(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    // Konstruktorlar
    public SecurityLog() {
        this.timestamp = LocalDateTime.now();
    }

    public SecurityLog(ThreatType threatType, String ipAddress, String description) {
        this();
        this.threatType = threatType;
        this.ipAddress = ipAddress;
        this.description = description;
        this.severity = determineSeverity(threatType);
    }

    // Xavflilik darajasini aniqlash
    private Severity determineSeverity(ThreatType threatType) {
        return switch (threatType) {
            case SQL_INJECTION -> Severity.CRITICAL;
            case XSS_ATTACK -> Severity.HIGH;
            case BRUTE_FORCE -> Severity.HIGH;
            case RATE_LIMIT_EXCEEDED -> Severity.MEDIUM;
            case SUSPICIOUS_REQUEST -> Severity.MEDIUM;
            case FAILED_LOGIN -> Severity.LOW;
        };
    }

    // Getter va Setter metodlar
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ThreatType getThreatType() {
        return threatType;
    }

    public void setThreatType(ThreatType threatType) {
        this.threatType = threatType;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public void setRequestUrl(String requestUrl) {
        this.requestUrl = requestUrl;
    }

    public String getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod;
    }

    public String getAttackPayload() {
        return attackPayload;
    }

    public void setAttackPayload(String attackPayload) {
        this.attackPayload = attackPayload;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
