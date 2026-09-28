package net.jdesive.secy.service.scoring;

import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;

/**
 * Where in the SDLC a {@link VulnerabilityAlert}'s finding was observed (M1i's
 * {@link ScoreInput#LIFECYCLE_PRESENCE} input) — the M1e {@link SbomLifecycleStage} of the SBOM an
 * SBOM-derived alert's component belongs to, or {@link #ASSET_OBSERVED} for a scanner-derived one.
 *
 * <p><b>Unknown is neutral, not discounted.</b> {@link #STAGE_UNKNOWN} (no component, or a
 * stage-less/legacy SBOM) and {@link #ASSET_OBSERVED} both carry weight {@code 1.0} in
 * {@link ScoringWeights#DEFAULT} — "assume the worst when unknown". Only {@link #SOURCE} is
 * discounted: a vulnerability declared in source but never observed downstream is a real, if
 * smaller, statement of risk. This also means a product whose only estate is a GitHub-connector
 * SBOM (always {@link SbomLifecycleStage#SOURCE}) is discounted by construction — declared-not-
 * confirmed, not "not a problem".
 */
public enum LifecyclePresence {

    DEPLOYED,
    ANALYZED,
    BUILD,
    SOURCE,

    /** No component, or a component whose SBOM carries no lifecycle stage (legacy/unstaged upload). */
    STAGE_UNKNOWN,

    /** The alert's component came from a scanner (an {@code Asset}), not an SBOM. */
    ASSET_OBSERVED;

    /** Reads {@code alert}'s component chain null-safely; never throws. */
    public static LifecyclePresence of(VulnerabilityAlert alert) {
        if (alert.getAssetComponent() != null) {
            return ASSET_OBSERVED;
        }
        SBOMComponent component = alert.getComponent();
        SbomLifecycleStage stage = component == null || component.getSbom() == null
                ? null
                : component.getSbom().getLifecycleStage();
        if (stage == null) {
            return STAGE_UNKNOWN;
        }
        return switch (stage) {
            case SOURCE -> SOURCE;
            case BUILD -> BUILD;
            case ANALYZED -> ANALYZED;
            case DEPLOYED -> DEPLOYED;
        };
    }

}
