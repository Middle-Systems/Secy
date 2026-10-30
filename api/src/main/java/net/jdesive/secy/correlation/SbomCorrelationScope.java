package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.SBOM;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * M1e's fix for the correlation-scope half of the active-SBOM-slot change: a staged SBOM's "product
 * truth" is not just itself, it's the union of the product's current stage slots.
 *
 * <h2>Why this exists</h2>
 *
 * <p>M1e relaxed the active-SBOM invariant from one-per-product to one-per-(product, stage), so a
 * Source and a Build SBOM can be simultaneously active for the same product. Without a matching
 * change here, {@code CorrelationService.correlate(SBOM)} and {@code CompromiseDetectionService.detect(SBOM)}
 * would still build their match set from a single SBOM's own components while reconciling against
 * the whole product's prior alerts — correlating a new Build SBOM would auto-resolve every alert on a
 * Source-only component, and the next Source upload would revive them, flip-flopping forever.
 *
 * <p>The fix: a staged, product-scoped SBOM's match set is built from every stage's current active
 * SBOM, not just the one that triggered the run — "a staged SBOM's product truth = the current SBOM
 * of every stage slot".
 *
 * <h2>What does NOT change</h2>
 *
 * <p>The bucket (M1a), a product-less SBOM, and every stage-<b>less</b> SBOM (every fixture that
 * predates M1e) all get exactly the same single-SBOM scope they always have — see
 * {@link #sbomsInScope}. Nothing about {@code productScoped}'s meaning or the Unassigned-bucket
 * carve-out changes.
 */
@Component
@RequiredArgsConstructor
public class SbomCorrelationScope {

    private final SBOMRepository sbomRepository;

    /**
     * The SBOMs whose components together make up {@code sbom}'s scope for one correlation/detection
     * run.
     *
     * <p>Returns {@code List.of(sbom)} — exactly today's behaviour — whenever {@code !productScoped}
     * (the bucket, or a product-less SBOM) or {@code sbom.getLifecycleStage() == null} (every
     * stage-less SBOM, which includes every fixture that predates M1e). Otherwise returns
     * {@code sbom} plus every other active staged sibling of its product
     * ({@link SBOMRepository#findActiveStagedSiblings}), ordered <b>ascending</b> by
     * {@link net.jdesive.secy.persistence.entity.SbomLifecycleStage#downstreamRank()} — SOURCE, then
     * BUILD, then ANALYZED, then DEPLOYED. At most one SBOM exists per stage (the M1e slot rule), so
     * this order is total.
     *
     * <p>Callers that build their match map with {@code Map::put} while iterating this list in order
     * get "most-downstream stage wins" for free: a later (more downstream) stage's row for a shared
     * component identity overwrites an earlier one's.
     */
    public List<SBOM> sbomsInScope(SBOM sbom, boolean productScoped) {
        if (!productScoped || sbom.getLifecycleStage() == null) {
            return List.of(sbom);
        }

        List<SBOM> siblings = sbomRepository.findActiveStagedSiblings(
                sbom.getProduct().getId(), sbom.getLifecycleStage(), sbom.getId());

        List<SBOM> scope = new ArrayList<>(siblings.size() + 1);
        scope.add(sbom);
        scope.addAll(siblings);
        scope.sort(Comparator.comparingInt(s -> s.getLifecycleStage().downstreamRank()));
        return scope;
    }

}
