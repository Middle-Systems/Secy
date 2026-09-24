package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.entity.Product;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;

    @Transactional(readOnly = true)
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Product getProductById(UUID id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
    }

    /**
     * Create a manually-added catalog product.
     *
     * <p>M1a guards, all enforced here rather than trusting the {@code @RequestBody} bind: the
     * {@code unassigned} flag is forced {@code false} regardless of what the client sent (it is also
     * {@code @JsonProperty(access = READ_ONLY)} on the entity, so this is belt-and-suspenders), the
     * name is trimmed, the reserved {@link Product#UNASSIGNED_NAME} name is rejected so no manual
     * product can ever collide with or masquerade as the bucket, and a blank {@code tagValue} is
     * normalized to {@code null} (an empty string would otherwise fight the tenant-scoped uniqueness
     * constraint the moment a second product tried the same thing).
     */
    @Transactional
    public Product createProduct(Product product) {
        product.setUnassigned(false);

        String name = product.getName() == null ? null : product.getName().trim();
        if (name != null && name.equalsIgnoreCase(Product.UNASSIGNED_NAME)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "\"" + Product.UNASSIGNED_NAME + "\" is reserved for the untagged-SBOM bucket");
        }
        product.setName(name);

        String tagValue = product.getTagValue() == null ? null : product.getTagValue().trim();
        if (tagValue != null && tagValue.isEmpty()) {
            tagValue = null;
        }
        if (tagValue != null && tagValue.equalsIgnoreCase("unassigned")) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "\"unassigned\" is reserved and cannot be used as a tag value");
        }
        product.setTagValue(tagValue);

        return productRepository.save(product);
    }

    /**
     * Find the product named {@code name}, or create it. Backs the GitHub connector sync, where
     * {@code owner/repo} is the product name and re-syncing the same repo must land on the same
     * product rather than raising a unique-constraint violation on {@code products.name}, which is
     * unique per tenant (not globally) as of migration 018 — unambiguous while only the default
     * tenant exists.
     *
     * <p>TODO(M2): once GitHub sync reads repo topics/custom-properties, this call site should be
     * replaced with {@link ProductTaggingService#resolveProduct} so GitHub-sourced products go
     * through the same tag-driven resolution as a manual tagged upload, rather than the
     * one-product-per-repo rule this method encodes.
     */
    @Transactional
    public Product findOrCreateByName(String name) {
        return productRepository.findByName(name).orElseGet(() -> {
            Product product = new Product();
            product.setName(name);
            return productRepository.save(product);
        });
    }

    /**
     * The per-tenant Unassigned bucket, creating it if this tenant has never needed one before.
     *
     * <p>Resolution order: 1) an existing bucket row for this tenant; 2) a pre-existing product
     * literally named {@link Product#UNASSIGNED_NAME} (adopted in place, matching migration
     * {@code 019c}'s backfill so a hand-created "Unassigned" product from before this migration isn't
     * duplicated); 3) a freshly created bucket row.
     */
    @Transactional
    public Product getOrCreateUnassigned(UUID tenantId) {
        return productRepository.findByTenantIdAndUnassignedTrue(tenantId)
                .or(() -> productRepository.findByTenantIdAndName(tenantId, Product.UNASSIGNED_NAME)
                        .map(existing -> {
                            existing.setUnassigned(true);
                            return productRepository.save(existing);
                        }))
                .orElseGet(() -> {
                    Product bucket = new Product();
                    bucket.setTenantId(tenantId);
                    bucket.setName(Product.UNASSIGNED_NAME);
                    bucket.setDescription("SBOMs that arrived without the tenant's product tag. "
                            + "Visible to security engineers for triage.");
                    bucket.setUnassigned(true);
                    return productRepository.save(bucket);
                });
    }

    /**
     * Find the product answering to {@code tagValue} within a tenant, or create it.
     *
     * <p>Resolution order: 1) a product already answering to this exact tag value; 2) an existing
     * product whose display name matches {@code tagValue} — adopted by setting its {@code tagValue}
     * so a manually created product picks up automatic resolution the first time a tag names it,
     * <em>unless</em> that name-match is already answering to a different tag value, which is a
     * conflict, not an adoption; 3) a freshly created product named after the tag value.
     */
    @Transactional
    public Product findOrCreateByTagValue(UUID tenantId, String tagValue) {
        return productRepository.findByTenantIdAndTagValue(tenantId, tagValue)
                .or(() -> productRepository.findByTenantIdAndName(tenantId, tagValue).map(existing -> {
                    if (existing.isUnassigned()) {
                        // Falls through to the create-new branch below; the bucket never adopts a tag.
                        return null;
                    }
                    if (existing.getTagValue() != null && !existing.getTagValue().equals(tagValue)) {
                        throw new InvalidProductTagException("product '" + existing.getName()
                                + "' already answers to tag value '" + existing.getTagValue() + "'");
                    }
                    existing.setTagValue(tagValue);
                    return productRepository.save(existing);
                }))
                .orElseGet(() -> {
                    Product product = new Product();
                    product.setTenantId(tenantId);
                    product.setName(tagValue);
                    product.setTagValue(tagValue);
                    return productRepository.save(product);
                });
    }

    /**
     * Delete a product and everything cascading from it. The Unassigned bucket can never be
     * deleted (409) — an unknown id stays a no-op, matching the pre-M1a behaviour, rather than
     * becoming a 404.
     */
    @Transactional
    public void deleteProduct(UUID id) {
        productRepository.findById(id).ifPresent(product -> {
            if (product.isUnassigned()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "The Unassigned product can't be deleted");
            }
            productRepository.deleteById(id);
        });
    }
}
