package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.ProductTagConfigRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.ProductTagConfig;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * M1a's tag-driven product resolution (see ROADMAP.md's "M1a — Tag-driven products").
 *
 * <p>{@link #resolveProduct} is <b>the</b> seam every future tag source funnels through — the manual
 * {@code tag=key=value} upload params today, and (per the roadmap) M2's GitHub repo topics/
 * custom-properties and M3's AWS/Azure resource tags later. Do not add a second resolution path
 * when those land; extend the callers to build a {@code Map<String, String>} of whatever tags they
 * have and call this instead.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ProductTaggingService {

    private final ProductTagConfigRepository productTagConfigRepository;
    private final ProductService productService;

    /** The tag key this tenant resolves products by — {@link ProductTagConfig#DEFAULT_TAG_KEY} if unconfigured. */
    @Transactional(readOnly = true)
    public String getTagKey(UUID tenantId) {
        return productTagConfigRepository.findByTenantId(tenantId)
                .map(ProductTagConfig::getTagKey)
                .orElse(ProductTagConfig.DEFAULT_TAG_KEY);
    }

    /**
     * Set the tenant's tag key. Forward-only: this never re-resolves any SBOM or product that
     * already exists, it only changes what a future {@link #resolveProduct} call does.
     *
     * @throws InvalidProductTagException if {@code tagKey} is null/blank, contains {@code '='} or
     *                                     whitespace, or exceeds {@link ProductTagConfig#MAX_TAG_KEY}
     *                                     characters
     */
    @Transactional
    public ProductTagConfig setTagKey(UUID tenantId, String tagKey) {
        String trimmed = tagKey == null ? null : tagKey.trim();
        if (trimmed == null || trimmed.isEmpty() || trimmed.length() > ProductTagConfig.MAX_TAG_KEY
                || !trimmed.matches(ProductTagConfig.TAG_KEY_REGEX)) {
            throw new InvalidProductTagException(
                    "'" + tagKey + "' is not a valid tag key — expected 1-" + ProductTagConfig.MAX_TAG_KEY
                            + " characters matching " + ProductTagConfig.TAG_KEY_REGEX);
        }

        ProductTagConfig config = productTagConfigRepository.findByTenantId(tenantId).orElseGet(() -> {
            ProductTagConfig fresh = new ProductTagConfig();
            fresh.setTenantId(tenantId);
            return fresh;
        });
        config.setTagKey(trimmed);
        return productTagConfigRepository.save(config);
    }

    /**
     * Resolve which product a set of tags belongs to.
     *
     * <p>Rule: if the tenant's configured key (case-insensitive match) is present in {@code tags}
     * with a non-blank value that isn't the reserved word {@code "unassigned"} (case-insensitive),
     * the tag value (trimmed) identifies the product — reused if a product already answers to it,
     * created otherwise. Everything else — no tags, no matching key, a blank value, or the value
     * {@code "unassigned"} — lands in the tenant's Unassigned bucket.
     *
     * @throws InvalidProductTagException if the resolved tag value exceeds 255 characters
     */
    @Transactional
    public Product resolveProduct(UUID tenantId, Map<String, String> tags) {
        String key = getTagKey(tenantId);
        String value = findValueIgnoreCase(tags, key);
        String trimmedValue = value == null ? null : value.trim();

        if (trimmedValue == null || trimmedValue.isEmpty() || trimmedValue.equalsIgnoreCase("unassigned")) {
            log.info("Resolving product for tenant {} by tag key '{}': no usable value (raw='{}') -> Unassigned",
                    tenantId, key, value);
            return productService.getOrCreateUnassigned(tenantId);
        }

        if (trimmedValue.length() > 255) {
            throw new InvalidProductTagException(
                    "tag value for key '" + key + "' is " + trimmedValue.length()
                            + " characters, over the 255 limit");
        }

        Product product = productService.findOrCreateByTagValue(tenantId, trimmedValue);
        log.info("Resolved product for tenant {} by tag key '{}'='{}' -> product {} ({})",
                tenantId, key, trimmedValue, product.getId(), product.getName());
        return product;
    }

    private static String findValueIgnoreCase(Map<String, String> tags, String key) {
        if (tags == null || tags.isEmpty()) {
            return null;
        }
        for (Map.Entry<String, String> entry : tags.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Parse repeated {@code tag=key=value} query params into an insertion-ordered map. Split on the
     * <em>first</em> {@code '='} only, so a value may itself contain {@code '='}. Pure/static so it's
     * unit-testable without a Spring context.
     *
     * @throws InvalidProductTagException if an entry has no {@code '='}, a blank key, or the same
     *                                     key (case-insensitively) is given more than once
     */
    public static Map<String, String> parseTagParams(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }

        Map<String, String> result = new LinkedHashMap<>();
        Map<String, String> seenKeys = new LinkedHashMap<>(); // lower-cased key -> original, for the duplicate message
        for (String entry : raw) {
            int eq = entry == null ? -1 : entry.indexOf('=');
            if (eq <= 0) {
                throw new InvalidProductTagException(
                        "malformed tag param '" + entry + "' — expected key=value");
            }
            String key = entry.substring(0, eq).trim();
            String value = entry.substring(eq + 1).trim();
            if (key.isEmpty()) {
                throw new InvalidProductTagException(
                        "malformed tag param '" + entry + "' — expected key=value");
            }

            String lowerKey = key.toLowerCase();
            if (seenKeys.containsKey(lowerKey)) {
                throw new InvalidProductTagException("tag key '" + key + "' given more than once");
            }
            seenKeys.put(lowerKey, key);
            result.put(key, value);
        }
        return result;
    }
}
