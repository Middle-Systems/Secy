package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * {@code GET /actionable/{id}} — the row, plus the full CVE, every component the same CVE affects,
 * and the raw feed evidence behind the verdict.
 *
 * <p>Mapped explicitly from the entities rather than serialized off them: the alert's relations are
 * lazy, and a detail view is exactly where an accidental proxy or a cascade into
 * {@code Vulnerability.alerts} would turn one request into thousands of queries.
 */
public record ActionableDetailResponse(
        UUID id,
        boolean actionable,
        ActionableReason actionableReason,
        Double cvssScore,
        Double epssScore,
        Double epssPercentile,
        ExploitMaturity exploitMaturity,
        FixState fixState,
        String fixedVersions,
        FixSource fixSource,
        LocalDate kevDueDate,
        String knownRansomwareUse,
        LocalDateTime createdAt,
        Cve cve,
        /** Every alert for the same CVE, including this one — "what else is affected". */
        List<AffectedComponent> affectedComponents,
        /** The CISA KEV entry, or null when the CVE is not KEV-listed. */
        KevEvidence kev,
        /** The FIRST EPSS entry, or null when the CVE has no EPSS row. */
        EpssEvidence epss,
        /** CVE references from NVD. */
        List<ReferenceLink> references) {

    /** The CVE itself, flattened out of {@code Vulnerability}. */
    public record Cve(
            String id,
            String sourceIdentifier,
            LocalDateTime published,
            LocalDateTime lastModified,
            String vulnStatus,
            String description,
            String baseSeverity,
            Double cvssScore,
            Double exploitabilityScore,
            Double impactScore,
            String cwe,
            String accessVector,
            String accessComplexity,
            String authenticationRequired,
            String confidentialityImpact,
            String integrityImpact,
            String availabilityImpact,
            boolean userInteractionRequired) {
    }

    /**
     * One (alert, component) pair the CVE affects. Phase 4 adds assets alongside SBOM components;
     * the shape is already asset-shaped ({@code assetId} stays null until then).
     */
    public record AffectedComponent(
            UUID alertId,
            UUID componentId,
            String name,
            String version,
            String purl,
            UUID sbomId,
            UUID productId,
            String productName,
            UUID assetId) {
    }

    /** The CISA KEV catalog entry, verbatim. */
    public record KevEvidence(
            String cveId,
            String vendor,
            String product,
            String name,
            LocalDateTime added,
            String description,
            String requiredActions,
            LocalDate dueDate,
            String knownRansomwareCampaignUse,
            String notes) {
    }

    /** The FIRST EPSS entry, verbatim. */
    public record EpssEvidence(
            String cve,
            Double epss,
            Double percentile,
            LocalDateTime date) {
    }

    /** An NVD reference URL. */
    public record ReferenceLink(String url, String source, String tags) {
    }

}
