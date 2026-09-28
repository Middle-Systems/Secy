package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.model.vex.VexStatementRole;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.model.scoring.RiskScoreBreakdown;

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
        /** How firmly correlation identified the affected component: EXACT / RANGE / HEURISTIC. */
        MatchConfidence matchConfidence,
        /**
         * ACTIVE, or AUTO_RESOLVED when the last correlation of the owning SBOM no longer reproduced
         * the match. The list endpoint returns only ACTIVE rows; this endpoint resolves both, so a
         * deep link to a resolved alert still opens.
         */
        AlertLifecycleState lifecycleState,
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
        List<ReferenceLink> references,
        /**
         * M1f: the alert's VEX resolution, plus every statement that applied and its role
         * ({@code WON}/{@code AGREES}/{@code CONFLICTING}/{@code OVERRIDDEN}/{@code SUPERSEDED}) — how
         * an operator sees which statements factored into the verdict, not just the verdict itself.
         * {@code status}/{@code justification}/{@code conflict}/{@code winningStatementId}/
         * {@code updatedAt} come from the alert's own stored columns (consistent with the list
         * endpoint); {@code statements} and {@code policy} are freshly computed by
         * {@code VexResolutionService.explain} so a stale precedence-policy read never happens.
         */
        Vex vex,
        /** M1i: the alert's stored risk score — matches the list row exactly. */
        Double riskScore,
        /**
         * M1i: the fresh, full breakdown behind {@link #riskScore} — {@code RiskScoringService.explain}
         * recomputed against this alert's <em>current</em> snapshots, the same stored-vs-fresh pattern
         * as {@link #vex}. {@code current} is false when a re-enrichment or rescore is due.
         */
        RiskScoreBreakdown riskScoreBreakdown) {

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
     * One (alert, component) pair the CVE affects, from either estate.
     *
     * <p>An SBOM-derived entry carries {@code sbomId}/{@code productId}/{@code productName} and no
     * asset; an asset-derived one (Phase 4) carries {@code assetId}/{@code assetName} and none of the
     * three. That is what makes this list answer the question it exists for — "everything this CVE
     * affects" — across what is shipped and what is running, in one place.
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
            UUID assetId,
            String assetName) {
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

    /** M1f's VEX block — see the field Javadoc above. Empty {@code statements} when nothing applies. */
    public record Vex(VexStatus status, VexJustification justification, boolean conflict, UUID winningStatementId,
                      VexPrecedencePolicy policy, LocalDateTime updatedAt, List<AppliedVexStatement> statements) {
    }

    /** One statement that applied to this alert, with the role {@code VexResolver} gave it. */
    public record AppliedVexStatement(UUID statementId, UUID documentId, VexDocumentFormat format, VexOrigin origin,
                                      String author, VexStatus status, String sourceStatus,
                                      VexJustification justification, String sourceJustification,
                                      String impactStatement, String actionStatement, String productRef,
                                      String targetPurl, String matchVersion, LocalDateTime statementTimestamp,
                                      VexStatementRole role) {
    }

}
