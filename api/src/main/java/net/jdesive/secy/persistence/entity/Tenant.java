package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A tenant — the unit of isolation M1 onward scopes every product, SBOM, asset, alert and finding
 * to (see ROADMAP.md, M0 — "Tenancy foundation (schema only)").
 *
 * <p>M0 ships the schema only: one hardcoded {@link #DEFAULT_TENANT_ID} row that every existing
 * (and, via {@link TenantOwnedEntity}, every newly created) row is attributed to. There is no
 * tenant CRUD, no tenant switching, and no request-scoped tenant context yet — those, along with
 * Postgres row-level security, per-tenant KMS, SSO and the audit log, belong to the dedicated
 * <b>Tenancy hardening</b> milestone.
 *
 * <h2>The default tenant row is not created via JPA</h2>
 *
 * <p>It is created by migration {@code 018a-tenant} in production, and by {@code import.sql} under
 * test. Never {@code save()} a {@code Tenant} with {@link #DEFAULT_TENANT_ID} preset as its id:
 * under {@link GenerationType#UUID}, Hibernate treats an entity with a non-null id as detached, so
 * a save would attempt an {@code UPDATE} against a row that (outside those two seeding paths) may
 * not exist, rather than an {@code INSERT}.
 */
@Getter
@Setter
@Entity
@Table(name = "tenant", uniqueConstraints = @UniqueConstraint(name = "uq_tenant_slug", columnNames = "slug"))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Tenant {

    /** The one tenant that exists in M0. Every {@link TenantOwnedEntity} defaults to this id. */
    public static final UUID DEFAULT_TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    public static final String DEFAULT_TENANT_SLUG = "default";

    public static final String DEFAULT_TENANT_NAME = "Default";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 255)
    private String name;

    /**
     * DNS-label-safe (63 chars, lowercase alphanumeric plus internal hyphens), leaving room for
     * future {@code slug.secy.example} tenant routing.
     */
    @Column(nullable = false, length = 63)
    @Pattern(regexp = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    private String slug;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
