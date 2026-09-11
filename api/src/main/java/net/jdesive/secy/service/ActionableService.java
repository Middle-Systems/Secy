package net.jdesive.secy.service;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Reads for the Actionable Items screen.
 *
 * <p>Every predicate here runs against the denormalized columns {@link EnrichmentService} wrote —
 * no join to {@code kev} or {@code epss} at request time. The trade is that the list reflects the
 * funnel as of the last enrichment; the re-enrichment that follows every KEV/EPSS ingest is what
 * keeps that honest.
 */
@Service
@RequiredArgsConstructor
public class ActionableService {

    /** How much CVE description a table row gets before it is cut short. */
    private static final int SUMMARY_LENGTH = 280;

    /** Sorts below every real EPSS score, so "no EPSS data" lands at the bottom rather than the top. */
    private static final double NO_EPSS = -1.0d;

    private final VulnerabilityAlertRepository alertRepository;

    /**
     * Paged actionable items, EPSS descending with unscored CVEs last.
     *
     * <p>The sort is fixed rather than caller-supplied: "what is most likely to be exploited" is
     * the whole point of the screen, and a null EPSS must not float to the top of a descending sort
     * the way PostgreSQL would default to. It is expressed as a coalesce inside the specification
     * so the ordering is identical on PostgreSQL and on the H2 the tests run against.
     */
    @Transactional(readOnly = true)
    public Page<ActionableItemResponse> findActionable(int page, int size, ActionableFilter filter) {
        Pageable pageable = PageRequest.of(page, size);
        return alertRepository.findAll(specification(filter), pageable).map(ActionableService::toRow);
    }

    /** Full detail for one alert, or empty when the id is unknown. */
    @Transactional(readOnly = true)
    public Optional<ActionableDetailResponse> findDetail(UUID id) {
        return alertRepository.findById(id).map(this::toDetail);
    }

    /* ------------------------------------------------------------------ */
    /* Query                                                              */
    /* ------------------------------------------------------------------ */

    private static Specification<VulnerabilityAlert> specification(ActionableFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // The two non-negotiable clauses: this endpoint is the funnel's output, and it shows
            // what is still true. An alert a re-scan no longer reproduces is kept (history, and any
            // triage done to it) but auto-resolved, and auto-resolved rows are not work.
            predicates.add(cb.isTrue(root.get("actionable")));
            predicates.add(cb.equal(root.get("lifecycleState"), AlertLifecycleState.ACTIVE));

            if (filter.reason() != null) {
                predicates.add(cb.equal(root.get("actionableReason"), filter.reason()));
            }
            if (filter.minCvss() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("cvssScore"), filter.minCvss()));
            }
            if (filter.fixState() != null) {
                predicates.add(cb.equal(root.get("fixState"), filter.fixState()));
            }
            if (filter.matchConfidence() != null) {
                predicates.add(cb.equal(root.get("matchConfidence"), filter.matchConfidence()));
            }
            if (filter.minExploitMaturity() != null && filter.minExploitMaturity() != ExploitMaturity.NONE) {
                // The enum is persisted as a string, so "at or above" is an IN over the tail of the
                // declaration order rather than a `>=` on the column.
                predicates.add(root.get("exploitMaturity").in(filter.minExploitMaturity().andAbove()));
            }
            if (filter.productId() != null) {
                Join<VulnerabilityAlert, SBOMComponent> component = root.join("component", JoinType.INNER);
                Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            // filter.assetId() and filter.state() are accepted for forward compatibility and have
            // nothing to bind to yet — see ActionableFilter.

            // Spring Data only overwrites the ORDER BY when the Pageable carries a Sort, and the
            // service always passes an unsorted one; the count query must not get an ORDER BY at all.
            if (!isCountQuery(query.getResultType())) {
                query.orderBy(
                        cb.desc(cb.coalesce(root.<Double>get("epssScore"), NO_EPSS)),
                        cb.desc(root.get("createdAt")),
                        cb.asc(root.get("id")));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private static boolean isCountQuery(Class<?> resultType) {
        return Long.class.equals(resultType) || long.class.equals(resultType);
    }

    /* ------------------------------------------------------------------ */
    /* Mapping                                                            */
    /* ------------------------------------------------------------------ */

    private static ActionableItemResponse toRow(VulnerabilityAlert alert) {
        Vulnerability cve = alert.getVulnerability();
        SBOMComponent component = alert.getComponent();
        Product product = productOf(component);

        return new ActionableItemResponse(
                alert.getId(),
                cve == null ? null : cve.getId(),
                cve == null ? null : summarize(cve.getDescription()),
                cve == null ? null : cve.getBaseSeverity(),
                alert.getCvssScore(),
                alert.getEpssScore(),
                alert.getEpssPercentile(),
                alert.getKevDueDate() != null
                        || alert.getActionableReason() == ActionableReason.KEV
                        || alert.getActionableReason() == ActionableReason.KEV_AND_EPSS_HIGH,
                alert.getKevDueDate(),
                alert.getKnownRansomwareUse(),
                alert.getExploitMaturity(),
                alert.getFixState(),
                alert.getFixedVersions(),
                alert.getFixSource(),
                alert.getMatchConfidence(),
                alert.getActionableReason(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                component == null ? null : component.getId(),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                alert.getCreatedAt());
    }

    private ActionableDetailResponse toDetail(VulnerabilityAlert alert) {
        Vulnerability cve = alert.getVulnerability();

        List<ActionableDetailResponse.AffectedComponent> affected = cve == null
                ? List.of()
                : alertRepository.findAllByVulnerabilityIdWithComponent(cve.getId()).stream()
                        .map(ActionableService::toAffected)
                        .sorted(Comparator.comparing(ActionableDetailResponse.AffectedComponent::alertId))
                        .toList();

        KEV kev = cve == null ? null : cve.getKev();
        EPSS epss = cve == null ? null : cve.getEpss();

        return new ActionableDetailResponse(
                alert.getId(),
                alert.isActionable(),
                alert.getActionableReason(),
                alert.getCvssScore(),
                alert.getEpssScore(),
                alert.getEpssPercentile(),
                alert.getExploitMaturity(),
                alert.getFixState(),
                alert.getFixedVersions(),
                alert.getFixSource(),
                alert.getMatchConfidence(),
                alert.getLifecycleState(),
                alert.getKevDueDate(),
                alert.getKnownRansomwareUse(),
                alert.getCreatedAt(),
                toCve(cve),
                affected,
                toKevEvidence(kev),
                toEpssEvidence(epss),
                toReferences(cve));
    }

    private static ActionableDetailResponse.Cve toCve(Vulnerability cve) {
        if (cve == null) {
            return null;
        }
        return new ActionableDetailResponse.Cve(
                cve.getId(),
                cve.getSourceIdentifier(),
                cve.getPublished(),
                cve.getLastModified(),
                cve.getVulnStatus(),
                cve.getDescription(),
                cve.getBaseSeverity(),
                cve.getCvssScore() == 0.0d ? null : cve.getCvssScore(),
                cve.getExploitabilityScore(),
                cve.getImpactScore(),
                cve.getCwe(),
                cve.getAccessVector(),
                cve.getAccessComplexity(),
                cve.getAuthenticationRequired(),
                cve.getConfidentialityImpact(),
                cve.getIntegrityImpact(),
                cve.getAvailabilityImpact(),
                cve.isUserInteractionRequired());
    }

    private static ActionableDetailResponse.AffectedComponent toAffected(VulnerabilityAlert alert) {
        SBOMComponent component = alert.getComponent();
        SBOM sbom = component == null ? null : component.getSbom();
        Product product = productOf(component);
        return new ActionableDetailResponse.AffectedComponent(
                alert.getId(),
                component == null ? null : component.getId(),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                sbom == null ? null : sbom.getId(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                null); // assetId — Phase 4
    }

    private static ActionableDetailResponse.KevEvidence toKevEvidence(KEV kev) {
        if (kev == null) {
            return null;
        }
        return new ActionableDetailResponse.KevEvidence(
                kev.getCveId(),
                kev.getVendor(),
                kev.getProduct(),
                kev.getName(),
                kev.getAdded(),
                kev.getDescription(),
                kev.getRequiredActions(),
                toLocalDate(kev.getDueDate()),
                kev.getKnownRansomwareCampaignUse(),
                kev.getNotes());
    }

    private static ActionableDetailResponse.EpssEvidence toEpssEvidence(EPSS epss) {
        if (epss == null) {
            return null;
        }
        return new ActionableDetailResponse.EpssEvidence(
                epss.getCve(),
                widen(epss.getEpss()),
                widen(epss.getPercentile()),
                epss.getDate());
    }

    private static List<ActionableDetailResponse.ReferenceLink> toReferences(Vulnerability cve) {
        if (cve == null || cve.getReferences() == null) {
            return List.of();
        }
        return cve.getReferences().stream()
                .map(r -> new ActionableDetailResponse.ReferenceLink(r.getUrl(), r.getSource(), r.getTags()))
                .toList();
    }

    private static Product productOf(SBOMComponent component) {
        if (component == null || component.getSbom() == null) {
            return null;
        }
        return component.getSbom().getProduct();
    }

    private static String summarize(String description) {
        if (description == null || description.length() <= SUMMARY_LENGTH) {
            return description;
        }
        return description.substring(0, SUMMARY_LENGTH) + "…";
    }

    /** See {@code EnrichmentService.widen} — a plain float→double cast invents decimals. */
    private static double widen(float value) {
        return Double.parseDouble(Float.toString(value));
    }

    /** See {@code EnrichmentService.toLocalDate} — {@code java.sql.Date.toInstant()} throws. */
    private static LocalDate toLocalDate(Date date) {
        if (date == null) {
            return null;
        }
        return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDate();
    }

}
