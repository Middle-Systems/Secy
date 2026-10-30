package net.jdesive.secy.persistence.entity;

import net.jdesive.secy.service.InvalidLifecycleStageException;

/**
 * Where in the SDLC an {@link SBOM} was captured (M1e, ROADMAP.md — "SBOM lifecycle stages +
 * diffing").
 *
 * <p><b>M1e writes this field.</b> It is set either from the {@code ?stage=} API param (wins when
 * present) or, failing that, from CycloneDX 1.5+ {@code metadata.lifecycles[]} (see
 * {@code CycloneDXNormalizer}); SPDX has no equivalent and always leaves it null. The GitHub
 * connector always writes {@link #SOURCE}. {@code null} means "stage unknown", never a default —
 * an unstaged SBOM is the pre-M1e "whole product truth" slot, which a staged upload supersedes
 * (see {@code SBOMService#createPlaceholder}).
 */
public enum SbomLifecycleStage {
    SOURCE,
    BUILD,
    ANALYZED,
    DEPLOYED;

    /**
     * Where this stage sits in the pipeline, ascending from the earliest ({@code SOURCE}) to the
     * latest ({@code DEPLOYED}). Used by {@code SbomCorrelationScope} to decide which of several
     * simultaneously-active stage SBOMs "wins" for a given component identity — the most downstream
     * one, since it is the closest observation to what is actually running.
     */
    public int downstreamRank() {
        return switch (this) {
            case SOURCE -> 1;
            case BUILD -> 2;
            case ANALYZED -> 3;
            case DEPLOYED -> 4;
        };
    }

    /**
     * Parses the {@code ?stage=} API param: null/blank is "not specified" ({@code null}), a
     * case-insensitive trimmed match on one of the four names is that stage, and anything else is a
     * client error.
     *
     * @throws InvalidLifecycleStageException when {@code raw} is non-blank and not one of the four
     *                                        stage names
     */
    public static SbomLifecycleStage fromApiValue(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        for (SbomLifecycleStage stage : values()) {
            if (stage.name().equalsIgnoreCase(trimmed)) {
                return stage;
            }
        }
        throw new InvalidLifecycleStageException(
                "Unknown lifecycle stage '" + raw + "' — expected one of SOURCE, BUILD, ANALYZED, DEPLOYED");
    }
}
