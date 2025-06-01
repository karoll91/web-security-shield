package uz.edu.security.websecurityshield.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Bloklangan IP manzillarini saqlash uchun Entity
 */
@Entity
@Table(name = "blocked_ips")
public class BlockedIP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", unique = true, nullable = false)
    private String ipAddress;

    @Column(name = "reason", nullable = false)
    private String reason;

    @Column(name = "blocked_at", nullable = false)
    private LocalDateTime blockedAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "is_permanent")
    private boolean permanent = false;

    @Column(name = "block_count")
    private int blockCount = 1;

    @Column(name = "last_attempt")
    private LocalDateTime lastAttempt;

    @Enumerated(EnumType.STRING)
    @Column(name = "block_type")
    private BlockType blockType;

    public enum BlockType {
        MANUAL("Qo'lda bloklangan"),
        AUTO_RATE_LIMIT("Avtomatik - Rate Limit"),
        AUTO_FAILED_LOGIN("Avtomatik - Login urinishlari"),
        AUTO_SUSPICIOUS("Avtomatik - Shubhali faoliyat"),
        AUTO_ATTACK("Avtomatik - Hujum aniqlangan");

        private final String displayName;

        BlockType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    // Konstruktorlar
    public BlockedIP() {
        this.blockedAt = LocalDateTime.now();
    }

    public BlockedIP(String ipAddress, String reason, BlockType blockType) {
        this();
        this.ipAddress = ipAddress;
        this.reason = reason;
        this.blockType = blockType;
        this.lastAttempt = LocalDateTime.now();
    }

    public BlockedIP(String ipAddress, String reason, BlockType blockType, int durationHours) {
        this(ipAddress, reason, blockType);
        if (durationHours > 0) {
            this.expiresAt = LocalDateTime.now().plusHours(durationHours);
            this.permanent = false;
        } else {
            this.permanent = true;
        }
    }

    // Foydali metodlar
    public boolean isExpired() {
        if (permanent) return false;
        if (expiresAt == null) return false;
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public void extendBlock(int additionalHours) {
        if (!permanent) {
            LocalDateTime now = LocalDateTime.now();
            if (expiresAt == null || expiresAt.isBefore(now)) {
                this.expiresAt = now.plusHours(additionalHours);
            } else {
                this.expiresAt = expiresAt.plusHours(additionalHours);
            }
            this.blockCount++;
            this.lastAttempt = now;
        }
    }

    public void makePermanent(String newReason) {
        this.permanent = true;
        this.expiresAt = null;
        this.reason = newReason;
    }

    // Getter va Setter metodlar
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getBlockedAt() {
        return blockedAt;
    }

    public void setBlockedAt(LocalDateTime blockedAt) {
        this.blockedAt = blockedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isPermanent() {
        return permanent;
    }

    public void setPermanent(boolean permanent) {
        this.permanent = permanent;
    }

    public int getBlockCount() {
        return blockCount;
    }

    public void setBlockCount(int blockCount) {
        this.blockCount = blockCount;
    }

    public LocalDateTime getLastAttempt() {
        return lastAttempt;
    }

    public void setLastAttempt(LocalDateTime lastAttempt) {
        this.lastAttempt = lastAttempt;
    }

    public BlockType getBlockType() {
        return blockType;
    }

    public void setBlockType(BlockType blockType) {
        this.blockType = blockType;
    }
}
