package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

/**
 * Base class for every entity M0 scopes to a tenant (ROADMAP.md, M0 — "Tenancy foundation (schema
 * only)"): {@link Product}, {@link SBOM}, {@link Asset}, {@link VulnerabilityAlert},
 * {@link CompromiseFinding}, {@link SourceConnector}, {@link DockerComplianceReport},
 * {@link ProductTagConfig} (M1a), {@link OwnershipLink} (M1b), {@link LifecycleDriftFinding}
 * (M1e), {@link VexDocument}, {@link VexStatement}, {@link VexPrecedenceConfig} (M1f),
 * {@link QuantumVulnerabilityFinding} (M1g), {@link SbomQualityFinding} (M1h), and
 * {@link ActionItem}, {@link ActionItemFinding}, {@link ActionItemEvent} (M1j). Future M1
 * tables should extend this too — don't build those now.
 *
 * <h2>Why a {@code @PrePersist} default instead of touching every creation site</h2>
 *
 * <p>M0 has no request-scoped tenant context — there is no logged-in tenant to read at the point a
 * {@code Product}, {@code Asset}, etc. gets created. Defaulting {@link #tenantId} to
 * {@link Tenant#DEFAULT_TENANT_ID} here, once, avoids threading a tenant id through
 * {@code ProductService}, {@code SBOMService}, {@code AssetService}, {@code CorrelationService},
 * {@code CompromiseDetectionService}, the GitHub/AWS/Azure sync services, the Spring Data REST
 * {@code POST /products} endpoint, and roughly seventeen test classes.
 *
 * <p><b>TODO(tenancy-hardening):</b> this fallback must be removed once there is a real tenant
 * context to assign from — see {@link #assignDefaultTenantIfUnset()}.
 *
 * <h2>Serialization</h2>
 *
 * <p>Both fields are field-level {@code @JsonIgnore}, which (with Lombok-generated accessors)
 * suppresses the property in both directions: it never appears in a response body, and a client
 * cannot set its own tenant by sending one in a request body bound straight to an entity (see
 * {@code ProductController#createProduct}, {@code SourceConnectorController#create}).
 *
 * <h2>Callback ordering</h2>
 *
 * <p>The JPA spec runs superclass {@code @PrePersist} callbacks before a subclass's own, and every
 * subclass here names its callback {@code onCreate}, not {@code assignDefaultTenantIfUnset}, so
 * there is no override/clash. Don't rename the existing {@code onCreate} methods to "merge" this.
 */
@Getter
@Setter
@MappedSuperclass
public abstract class TenantOwnedEntity {

    @JsonIgnore
    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @JsonIgnore
    @Setter(AccessLevel.NONE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", insertable = false, updatable = false)
    @ToString.Exclude
    private Tenant tenant;

    /**
     * Defaults {@link #tenantId} to {@link Tenant#DEFAULT_TENANT_ID} when nothing set one.
     *
     * <p><b>TODO(tenancy-hardening):</b> remove this fallback once a request-scoped tenant context
     * exists; every creation site should assign a real tenant explicitly from then on.
     */
    @PrePersist
    void assignDefaultTenantIfUnset() {
        if (tenantId == null) {
            tenantId = Tenant.DEFAULT_TENANT_ID;
        }
    }
}
