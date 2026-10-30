package net.jdesive.secy.persistence.entity;

/**
 * The discriminator of the M1j {@code Finding} read-model union (ROADMAP.md — "M1j — Finding &amp;
 * Action-item model"). Unlike {@code ActionableItemType}, which discriminates two tables joined by
 * one endpoint, this discriminates <b>five</b> existing tables plus one stub — see
 * {@code net.jdesive.secy.service.finding.FindingResolver} for how each value resolves.
 *
 * <p>{@code VULNERABILITY} → {@link VulnerabilityAlert}, {@code COMPROMISE} → {@link CompromiseFinding},
 * {@code LIFECYCLE_DRIFT} → {@link LifecycleDriftFinding}, {@code QUANTUM_VULNERABLE} →
 * {@link QuantumVulnerabilityFinding}, {@code SBOM_QUALITY} → {@link SbomQualityFinding}.
 *
 * <p>{@code PROVENANCE} is a pure stub — no backing table exists yet and none of this milestone's
 * code ever resolves one. M4 (supply-chain provenance verification) adds a {@code provenance_finding}
 * table and a {@code provenance_finding_id} column on {@code action_item_finding}; until then this
 * value exists only so the enum vocabulary and the {@code GET /findings/types} inventory are honest
 * about what M1's design doc promises, not what is built.
 */
public enum FindingType {

    VULNERABILITY,
    COMPROMISE,
    LIFECYCLE_DRIFT,
    QUANTUM_VULNERABLE,
    SBOM_QUALITY,

    /** Stub — see the class Javadoc. Never resolves; {@link #backedByTable()} is false. */
    PROVENANCE;

    /** False only for {@link #PROVENANCE} — every other value has a real backing table today. */
    public boolean backedByTable() {
        return this != PROVENANCE;
    }

}
