package net.jdesive.secy.service.scoring;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.scoring.RiskRollupResponse;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.service.ActionableService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * {@code GET /products/{id}/risk-score} and {@code GET /assets/{id}/risk-score} (M1i, ROADMAP.md —
 * "Scoring engine rework") — the <b>maximum</b> risk score among a scope's default {@code /actionable}
 * vulnerability population, computed on read from {@link ActionableService}'s rollup queries; nothing
 * here is stored. See {@link RiskRollupResponse}'s Javadoc for why max, not sum or average.
 *
 * <p>The XOR rule holds here too: a product's rollup only ever sees SBOM-derived alerts (an
 * {@code ActionableFilter} with {@code productId} set), an asset's only ever sees scanner-derived ones
 * ({@code assetId} set) — an asset linked to a product never leaks into that product's own rollup.
 */
@Service
@RequiredArgsConstructor
public class RiskRollupService {

    private final ActionableService actionableService;

    private final ProductRepository productRepository;

    private final AssetRepository assetRepository;

    @Transactional(readOnly = true)
    public Optional<RiskRollupResponse> forProduct(UUID productId) {
        return productRepository.findById(productId)
                .map(product -> build("PRODUCT", productId, product.getName(), productFilter(productId)));
    }

    @Transactional(readOnly = true)
    public Optional<RiskRollupResponse> forAsset(UUID assetId) {
        return assetRepository.findById(assetId)
                .map(asset -> build("ASSET", assetId, asset.getName(), assetFilter(assetId)));
    }

    private RiskRollupResponse build(String scopeType, UUID scopeId, String scopeName, ActionableFilter filter) {
        ActionableService.RollupCounts counts = actionableService.vulnerabilityRollup(filter);
        long compromiseCount = actionableService.compromiseCount(filter);
        return new RiskRollupResponse(
                scopeType,
                scopeId,
                scopeName,
                counts.maxScore(),
                counts.topFindingId(),
                counts.findingCount(),
                counts.unscoredFindingCount(),
                compromiseCount,
                ScoringWeights.DEFAULT.modelVersion());
    }

    /** Only {@code productId} set — the default {@code GET /actionable} population, scoped to one product. */
    private static ActionableFilter productFilter(UUID productId) {
        return new ActionableFilter(productId, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    /** Only {@code assetId} set — the mirror image, scoped to one asset. */
    private static ActionableFilter assetFilter(UUID assetId) {
        return new ActionableFilter(null, assetId, null, null, null, null, null, null, null, null, null, null, null);
    }

}
