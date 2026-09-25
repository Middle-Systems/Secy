package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Per-tenant {@link VexPrecedencePolicy} — {@code GET}/{@code PUT /vex/settings/precedence}. One row
 * per tenant ({@code uq_vex_precedence_config_tenant}, migration {@code 024a}, seeded with
 * {@link #DEFAULT_POLICY} for every tenant that existed when it ran).
 *
 * <p>A missing row falls back to {@link #DEFAULT_POLICY} on read — mirrors
 * {@code ProductTaggingService.getTagKey} — rather than being lazily created; a row is only ever
 * created by an explicit {@code PUT}.
 */
@Getter
@Setter
@Entity
@Table(name = "vex_precedence_config",
        uniqueConstraints = @UniqueConstraint(name = "uq_vex_precedence_config_tenant", columnNames = "tenant_id"))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class VexPrecedenceConfig extends TenantOwnedEntity {

    public static final VexPrecedencePolicy DEFAULT_POLICY = VexPrecedencePolicy.TENANT_OVER_VENDOR;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private VexPrecedencePolicy policy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
