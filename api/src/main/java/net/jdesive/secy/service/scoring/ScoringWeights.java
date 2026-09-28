package net.jdesive.secy.service.scoring;

import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The M1i risk-scoring formula's weights (ROADMAP.md — "M1i — Scoring engine rework") — the one
 * place. Tenant-configurable later is additive — a per-tenant row materialised into this record
 * behind {@link ScoringWeightsProvider} — not something this record's shape needs to anticipate
 * beyond that seam.
 *
 * <h2>Why a Java constant, not {@code @ConfigurationProperties}</h2>
 *
 * <p>Same reasoning as M1h's {@code SbomQualityScorer}: the test {@code application.properties}
 * <b>replaces</b>, rather than merges with, the main one, so every one of these ~30 enum-keyed
 * weights would need restating there too; and the shape (five maps keyed by four different enums) is
 * awkward to express as flat dotted properties. The future direction is a per-tenant DB-backed
 * config, not deployment properties, so there is nothing to gain by routing through Spring's
 * externalized-config machinery today.
 *
 * @param modelVersion           stamped onto every {@code VulnerabilityAlert.riskScoreModel} this
 *                               weights row produces — {@code "m1i.1"} for {@link #DEFAULT}
 * @param cvssPointsPerUnit      points per unit of the 0-10 CVSS scale ({@code ScoreInput.CVSS_BASE})
 * @param severityBandCvss       the 0-10-scale value substituted when {@code cvssScore} is null,
 *                               keyed by the upper-cased NVD severity band name; must have an entry
 *                               for every one of {@code NONE, LOW, MEDIUM, HIGH, CRITICAL}
 * @param unknownCvss            the 0-10-scale value used when neither a CVSS score nor a recognised
 *                               band is available — "unknown is not harmless"
 * @param kevPoints              flat points added when the alert's CVE is KEV-listed
 * @param epssMaxPoints          points at EPSS probability {@code 1.0}; scaled linearly below that
 * @param exploitMaturityPoints  flat points per {@link ExploitMaturity}, suppressed to 0 when
 *                               KEV-listed (KEV implies {@code IN_THE_WILD})
 * @param lifecycleFactor        multiplier per {@link LifecyclePresence}
 * @param vexFactor              multiplier per {@link VexScoringState}
 * @param dependencyDepthFactor  multiplier per {@link DependencyDepth} — every alert is
 *                               {@code UNKNOWN} until M1l
 * @param fixFactor              multiplier per {@link FixState}
 */
public record ScoringWeights(
        String modelVersion,
        double cvssPointsPerUnit,
        Map<String, Double> severityBandCvss,
        double unknownCvss,
        double kevPoints,
        double epssMaxPoints,
        Map<ExploitMaturity, Double> exploitMaturityPoints,
        Map<LifecyclePresence, Double> lifecycleFactor,
        Map<VexScoringState, Double> vexFactor,
        Map<DependencyDepth, Double> dependencyDepthFactor,
        Map<FixState, Double> fixFactor) {

    /** The severity band names {@link #severityBandCvss} must cover. Not an enum — NVD's band is a plain string. */
    private static final List<String> SEVERITY_BANDS = List.of("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL");

    public ScoringWeights {
        if (modelVersion == null || modelVersion.isBlank()) {
            throw new IllegalArgumentException("modelVersion must not be blank");
        }
        requireNonNegative("cvssPointsPerUnit", cvssPointsPerUnit);
        requireNonNegative("unknownCvss", unknownCvss);
        requireNonNegative("kevPoints", kevPoints);
        requireNonNegative("epssMaxPoints", epssMaxPoints);

        if (severityBandCvss == null) {
            throw new IllegalArgumentException("severityBandCvss must not be null");
        }
        Map<String, Double> severityCopy = Map.copyOf(severityBandCvss);
        for (String band : SEVERITY_BANDS) {
            Double value = severityCopy.get(band);
            if (value == null) {
                throw new IllegalArgumentException("severityBandCvss missing entry for " + band);
            }
            requireNonNegative("severityBandCvss[" + band + "]", value);
        }
        severityBandCvss = severityCopy;

        exploitMaturityPoints = copyEnumMap(exploitMaturityPoints, ExploitMaturity.class, "exploitMaturityPoints");
        for (ExploitMaturity m : ExploitMaturity.values()) {
            requireNonNegative("exploitMaturityPoints[" + m + "]", exploitMaturityPoints.get(m));
        }

        lifecycleFactor = copyEnumMap(lifecycleFactor, LifecyclePresence.class, "lifecycleFactor");
        for (LifecyclePresence p : LifecyclePresence.values()) {
            requireUnitInterval("lifecycleFactor[" + p + "]", lifecycleFactor.get(p));
        }

        vexFactor = copyEnumMap(vexFactor, VexScoringState.class, "vexFactor");
        for (VexScoringState v : VexScoringState.values()) {
            requireUnitInterval("vexFactor[" + v + "]", vexFactor.get(v));
        }

        dependencyDepthFactor = copyEnumMap(dependencyDepthFactor, DependencyDepth.class, "dependencyDepthFactor");
        for (DependencyDepth d : DependencyDepth.values()) {
            requireUnitInterval("dependencyDepthFactor[" + d + "]", dependencyDepthFactor.get(d));
        }

        fixFactor = copyEnumMap(fixFactor, FixState.class, "fixFactor");
        for (FixState f : FixState.values()) {
            requireUnitInterval("fixFactor[" + f + "]", fixFactor.get(f));
        }
    }

    private static <E extends Enum<E>> Map<E, Double> copyEnumMap(Map<E, Double> source, Class<E> type, String name) {
        if (source == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        Map<E, Double> copy = new EnumMap<>(type);
        copy.putAll(source);
        for (E constant : type.getEnumConstants()) {
            if (!copy.containsKey(constant)) {
                throw new IllegalArgumentException(name + " missing entry for " + constant);
            }
        }
        return Map.copyOf(copy);
    }

    private static void requireNonNegative(String name, Double value) {
        if (value == null || value < 0) {
            throw new IllegalArgumentException(name + " must be >= 0, was " + value);
        }
    }

    private static void requireUnitInterval(String name, Double value) {
        if (value == null || value < 0 || value > 1) {
            throw new IllegalArgumentException(name + " must be in [0,1], was " + value);
        }
    }

    /** The §3 formula table, model version {@code m1i.1}. */
    public static final ScoringWeights DEFAULT = new ScoringWeights(
            "m1i.1",
            4.0,
            Map.of("NONE", 0.0, "LOW", 2.0, "MEDIUM", 5.5, "HIGH", 8.0, "CRITICAL", 9.5),
            5.0,
            35.0,
            25.0,
            Map.of(
                    ExploitMaturity.NONE, 0.0,
                    ExploitMaturity.POC, 5.0,
                    ExploitMaturity.WEAPONIZED, 10.0,
                    ExploitMaturity.IN_THE_WILD, 15.0),
            Map.of(
                    LifecyclePresence.DEPLOYED, 1.0,
                    LifecyclePresence.ANALYZED, 0.9,
                    LifecyclePresence.BUILD, 0.8,
                    LifecyclePresence.SOURCE, 0.6,
                    LifecyclePresence.STAGE_UNKNOWN, 1.0,
                    LifecyclePresence.ASSET_OBSERVED, 1.0),
            Map.of(
                    VexScoringState.NONE, 1.0,
                    VexScoringState.AFFECTED, 1.0,
                    VexScoringState.UNDER_INVESTIGATION, 1.0,
                    VexScoringState.NOT_AFFECTED, 0.0,
                    VexScoringState.FIXED, 0.0,
                    VexScoringState.CONFLICT, 1.0),
            Map.of(
                    DependencyDepth.DIRECT, 1.0,
                    DependencyDepth.TRANSITIVE, 0.9,
                    DependencyDepth.UNKNOWN, 1.0),
            Map.of(
                    FixState.FIXED, 0.95,
                    FixState.NO_FIX, 1.0,
                    FixState.UNKNOWN, 1.0));

}
