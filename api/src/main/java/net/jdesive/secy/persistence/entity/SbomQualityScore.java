package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * One SBOM document's NTIA minimum-elements completeness score (M1h, ROADMAP.md — "M1h — SBOM
 * quality scoring"), 0-100. See {@code net.jdesive.secy.service.quality.SbomQualityScorer} for how
 * every field here is derived.
 *
 * <p>Embedded twice with the exact same column names: on {@link SBOM} itself (the score for that
 * one document — {@code null} means "not scored", i.e. the document had no non-crypto components),
 * and on {@link SbomQualityFinding} (a snapshot of the last low-scoring document that fed a
 * (product, stage-slot) finding). No {@code @AttributeOverrides} needed since the two live in
 * different tables.
 *
 * <p><b>Every field is a wrapper type, never a primitive.</b> A primitive would make Hibernate's H2
 * test DDL mark the column {@code NOT NULL}, which would break every insert of an unscored SBOM
 * (every SBOM whose document had zero non-crypto components, and every SBOM that predates M1h).
 */
@Getter
@Setter
@Embeddable
@NoArgsConstructor
public class SbomQualityScore {

    @Column(name = "quality_score")
    private Integer score;

    @Column(name = "quality_supplier_pct")
    private Integer supplierCoverage;

    @Column(name = "quality_name_pct")
    private Integer nameCoverage;

    @Column(name = "quality_version_pct")
    private Integer versionCoverage;

    @Column(name = "quality_unique_id_pct")
    private Integer uniqueIdCoverage;

    @Column(name = "quality_dependency_pct")
    private Integer dependencyCoverage;

    @Column(name = "quality_has_author")
    private Boolean hasAuthor;

    @Column(name = "quality_has_timestamp")
    private Boolean hasTimestamp;

    @Column(name = "quality_components_scored")
    private Integer componentsScored;

    /**
     * Derived getter, not a persisted field — Jackson serializes it as {@code missingElements}
     * because its name matches the {@code getXxx} bean-property convention. Each component element
     * whose coverage is below 100 first (fixed {@link NtiaElement} order), then {@code AUTHOR} if
     * {@link #hasAuthor} is not true, then {@code TIMESTAMP} if {@link #hasTimestamp} is not true.
     */
    public List<NtiaElement> getMissingElements() {
        List<NtiaElement> missing = new ArrayList<>();
        addIfIncomplete(missing, NtiaElement.SUPPLIER, supplierCoverage);
        addIfIncomplete(missing, NtiaElement.COMPONENT_NAME, nameCoverage);
        addIfIncomplete(missing, NtiaElement.COMPONENT_VERSION, versionCoverage);
        addIfIncomplete(missing, NtiaElement.UNIQUE_IDENTIFIER, uniqueIdCoverage);
        addIfIncomplete(missing, NtiaElement.DEPENDENCY_RELATIONSHIP, dependencyCoverage);
        if (hasAuthor == null || !hasAuthor) {
            missing.add(NtiaElement.AUTHOR);
        }
        if (hasTimestamp == null || !hasTimestamp) {
            missing.add(NtiaElement.TIMESTAMP);
        }
        return missing;
    }

    private static void addIfIncomplete(List<NtiaElement> missing, NtiaElement element, Integer coverage) {
        if (coverage == null || coverage < 100) {
            missing.add(element);
        }
    }

    /**
     * A fresh, independent copy of this score. <b>Not a bean-property getter</b> (its name does not
     * start with {@code get}/{@code is}), so Jackson never serializes it as a field — it exists only
     * so a finding's evidence snapshot never shares one embeddable instance with the SBOM row it was
     * read from.
     */
    public SbomQualityScore copy() {
        SbomQualityScore copy = new SbomQualityScore();
        copy.score = this.score;
        copy.supplierCoverage = this.supplierCoverage;
        copy.nameCoverage = this.nameCoverage;
        copy.versionCoverage = this.versionCoverage;
        copy.uniqueIdCoverage = this.uniqueIdCoverage;
        copy.dependencyCoverage = this.dependencyCoverage;
        copy.hasAuthor = this.hasAuthor;
        copy.hasTimestamp = this.hasTimestamp;
        copy.componentsScored = this.componentsScored;
        return copy;
    }

}
