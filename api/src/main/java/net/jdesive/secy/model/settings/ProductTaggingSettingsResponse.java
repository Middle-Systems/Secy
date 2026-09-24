package net.jdesive.secy.model.settings;

import net.jdesive.secy.persistence.entity.ProductTagConfig;

/**
 * {@code GET}/{@code PUT /settings/product-tagging} response. Never carries a tenant id — the
 * request itself is the tenant scope (today: always the default tenant, see the
 * {@code TODO(tenancy-hardening)} on {@link net.jdesive.secy.controller.ProductTaggingSettingsController}).
 */
public record ProductTaggingSettingsResponse(String tagKey, String defaultTagKey, boolean usingDefault) {

    public static ProductTaggingSettingsResponse of(String tagKey) {
        return new ProductTaggingSettingsResponse(tagKey, ProductTagConfig.DEFAULT_TAG_KEY,
                tagKey.equals(ProductTagConfig.DEFAULT_TAG_KEY));
    }
}
