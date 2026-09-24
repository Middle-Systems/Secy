package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Per-tenant configuration of the tag key {@link net.jdesive.secy.service.ProductTaggingService}
 * resolves products by (M1a — see ROADMAP.md's "M1a — Tag-driven products").
 *
 * <p>One row per tenant ({@code uq_product_tag_config_tenant}, migration {@code 019}). A tenant with
 * no row here is not mis-configured — {@link #DEFAULT_TAG_KEY} applies, exactly as if a row existed
 * with that value. Migration {@code 019a} seeds a row for every tenant that existed at the time it
 * ran, but nothing requires one to exist for a tenant created afterwards.
 *
 * <h2>Forward-only</h2>
 *
 * <p>Changing {@link #tagKey} only affects <em>future</em> resolutions — it never re-resolves SBOMs
 * or products that already exist. There is deliberately no "re-tag everything" job in M1a.
 */
@Getter
@Setter
@Entity
@Table(name = "product_tag_config",
        uniqueConstraints = @UniqueConstraint(name = "uq_product_tag_config_tenant", columnNames = "tenant_id"))
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class ProductTagConfig extends TenantOwnedEntity {

    /** The tag key a tenant answers to until it configures its own. */
    public static final String DEFAULT_TAG_KEY = "secy:product";

    public static final String TAG_KEY_REGEX = "^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$";

    public static final int MAX_TAG_KEY = 128;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tag_key", nullable = false, length = MAX_TAG_KEY)
    @Pattern(regexp = TAG_KEY_REGEX)
    private String tagKey;

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
