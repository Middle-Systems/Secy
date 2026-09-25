package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

/**
 * One entry of CycloneDX 1.5+ {@code metadata.lifecycles[]} — either a pre-defined {@code phase}
 * (the CycloneDX-standard vocabulary: {@code design}, {@code pre-build}, {@code build},
 * {@code post-build}, {@code operations}, {@code discovery}, {@code decommission}) or a custom
 * {@code name}/{@code description} pair. See {@code CycloneDXNormalizer} for how {@code phase} maps
 * to a {@link net.jdesive.secy.persistence.entity.SbomLifecycleStage} (M1e).
 */
@Data
public class CycloneDXLifecycle {

    private String phase;

    private String name;

    private String description;
}
