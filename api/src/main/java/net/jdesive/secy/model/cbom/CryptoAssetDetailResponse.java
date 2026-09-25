package net.jdesive.secy.model.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.entity.SBOMComponentCryptoAsset;

/**
 * {@code GET /cbom/assets/{id}} — everything {@link CryptoAssetResponse} has, plus the sanitized
 * {@code cryptoProperties} JSON tree ({@code relatedCryptoMaterialProperties.value} was never stored,
 * so it is never returned here either).
 */
public record CryptoAssetDetailResponse(CryptoAssetResponse asset, JsonNode cryptoProperties) {

    public static CryptoAssetDetailResponse from(SBOMComponentCryptoAsset entity, ObjectMapper mapper) {
        JsonNode cryptoProperties = null;
        String json = entity.getCryptoPropertiesJson();
        if (json != null && !json.isBlank()) {
            try {
                cryptoProperties = mapper.readTree(json);
            } catch (Exception ignored) {
                cryptoProperties = null;
            }
        }
        return new CryptoAssetDetailResponse(CryptoAssetResponse.from(entity), cryptoProperties);
    }

}
