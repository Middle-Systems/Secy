package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A product in the catalog — the unit SBOMs attach to.
 *
 * <h2>The Unassigned bucket (M1a)</h2>
 *
 * <p>Every tenant has exactly one {@link #unassigned} {@code Product} row, named
 * {@link #UNASSIGNED_NAME}: the landing spot for SBOMs uploaded via
 * {@code POST /sbom} whose tag doesn't resolve to a real product (no configured tag present, a
 * blank value, or the reserved value {@code "unassigned"}). It is a real, visible catalog row — not
 * a null-product sentinel — so it shows up like any other product, can hold many SBOMs, and its
 * SBOMs all stay {@code active} (see {@code SBOMService#createPlaceholder}) and correlate at their
 * own SBOM scope rather than the whole-product scope a normal product uses (see
 * {@code CorrelationService#correlate(SBOM)}). It cannot be deleted, renamed via a client-supplied
 * {@code unassigned} flag, or claimed by a user-created product's name. See
 * {@link net.jdesive.secy.service.ProductTaggingService#resolveProduct} for the resolution rule and
 * {@link net.jdesive.secy.service.ProductService#getOrCreateUnassigned} for how the row is created.
 */
@Getter
@Setter
@Entity
@Transactional
@Table(name = "products",
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_products_tenant_name", columnNames = {"tenant_id", "name"}),
                @UniqueConstraint(name = "uq_products_tenant_tag_value", columnNames = {"tenant_id", "tag_value"})
        })
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Product extends TenantOwnedEntity {

    /** Reserved display name for the per-tenant Unassigned bucket — see the class Javadoc. */
    public static final String UNASSIGNED_NAME = "Unassigned";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(length = 1024)
    private String description;

    private LocalDateTime createdAt;

    /**
     * True only for the per-tenant Unassigned bucket. Read-only over the API — a client can never
     * flip this via {@code POST /products}'s {@code @RequestBody} binding (see
     * {@link net.jdesive.secy.service.ProductService#createProduct}, which also forces it false on
     * every path that constructs a new row directly).
     */
    @Column(nullable = false)
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private boolean unassigned;

    /**
     * The tag value this product answers to (distinct from the display {@link #name}), set by
     * {@link net.jdesive.secy.service.ProductTaggingService#resolveProduct}. Nullable — a manually
     * created product need not answer to any tag.
     */
    @Column(name = "tag_value", length = 255)
    private String tagValue;

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    @JsonIgnoreProperties("product")
    private List<SBOM> sboms = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

}
