package net.jdesive.secy.service;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.model.component.CorrelatableComponent;
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

    /**
     * The actionable items for one asset — {@code GET /assets/{id}}'s embedded list.
     *
     * <p>Deliberately {@link #findActionable} with an asset filter and nothing else: an asset's
     * findings are rows of the same list the Actionable Items screen shows, with the same funnel, the
     * same sort and the same shape. Giving assets their own query would be the first step towards
     * giving them their own funnel, which is the trap the (now deleted) {@code DockerVulnerabilityAlert}
     * fell into. Phase 5 routes compliance-report findings through here too, so this one query backs
     * the Actionable Items screen, the Infrastructure drill-down and the Compliance detail alike.
     */
    @Transactional(readOnly = true)
    public Page<ActionableItemResponse> findActionableForAsset(int page, int size, UUID assetId) {
        return findActionable(page, size,
                new ActionableFilter(null, assetId, null, null, null, null, null, null));
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
                // INNER, so an asset-derived alert (whose `component` is null) is excluded by
                // construction — a product filter asks about what the product declares it ships, not
                // about what happens to be running on an asset someone linked to it.
                Join<VulnerabilityAlert, SBOMComponent> component = root.join("component", JoinType.INNER);
                Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            if (filter.assetId() != null) {
                // The mirror image, and real from Phase 4 on — this was an accepted-and-ignored no-op
                // in Phases 1-2. See ActionableFilter for the compatibility note.
                Join<VulnerabilityAlert, AssetComponent> assetComponent =
                        root.join("assetComponent", JoinType.INNER);
                predicates.add(cb.equal(assetComponent.get("asset").get("id"), filter.assetId()));
            }
            // filter.state() is accepted for forward compatibility and has nothing to bind to yet —
            // see ActionableFilter.

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

    /**
     * One row, from whichever kind of component the alert cites.
     *
     * <p>The component fields are filled from the SBOM component or the asset component — the table
     * renders them identically because they mean the same thing — while {@code productId} and
     * {@code assetId} say which estate the finding belongs to. Exactly one of the two is set.
     */
    private static ActionableItemResponse toRow(VulnerabilityAlert alert) {
        Vulnerability cve = alert.getVulnerability();
        CorrelatableComponent component = alert.getCorrelatableComponent();
        Product product = productOf(alert.getComponent());
        Asset asset = assetOf(alert.getAssetComponent());

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
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                componentIdOf(alert),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                alert.getCreatedAt());
    }

    /** The id of whichever component row the alert cites. */
    private static UUID componentIdOf(VulnerabilityAlert alert) {
        if (alert.getComponent() != null) {
            return alert.getComponent().getId();
        }
        return alert.getAssetComponent() == null ? null : alert.getAssetComponent().getId();
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
        CorrelatableComponent component = alert.getCorrelatableComponent();
        SBOM sbom = alert.getComponent() == null ? null : alert.getComponent().getSbom();
        Product product = productOf(alert.getComponent());
        Asset asset = assetOf(alert.getAssetComponent());
        return new ActionableDetailResponse.AffectedComponent(
                alert.getId(),
                componentIdOf(alert),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                sbom == null ? null : sbom.getId(),
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName());
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

    private static Asset assetOf(AssetComponent component) {
        return component == null ? null : component.getAsset();
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
