package net.jdesive.secy.service;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.model.actionable.ActionableItemType;
import net.jdesive.secy.model.actionable.OffsetLimitRequest;
import net.jdesive.secy.model.compromise.CompromiseFilter;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
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
 * Reads for the Actionable Items screen — the funnel's output, and since Phase 6 a <b>typed
 * union</b> over two tables.
 *
 * <p>Every vulnerability predicate here runs against the denormalized columns
 * {@link EnrichmentService} wrote — no join to {@code kev} or {@code epss} at request time. The
 * trade is that the list reflects the funnel as of the last enrichment; the re-enrichment that
 * follows every KEV/EPSS ingest is what keeps that honest.
 *
 * <h2>The third promotion path</h2>
 *
 * <p>An item is actionable when its CVE is KEV-listed, <b>or</b> its EPSS is above the threshold,
 * <b>or</b> it is a {@code CompromiseFinding}. The first two are one boolean column on
 * {@code vulnerability_alert}; the third is the existence of a row in a table with no join to the
 * alert table at all. See {@link #findActionable} for how the two are paged as one list.
 */
@Service
@RequiredArgsConstructor
public class ActionableService {

    /** How much CVE description a table row gets before it is cut short. */
    private static final int SUMMARY_LENGTH = 280;

    /** Sorts below every real EPSS score, so "no EPSS data" lands at the bottom rather than the top. */
    private static final double NO_EPSS = -1.0d;

    private final VulnerabilityAlertRepository alertRepository;

    private final CompromiseFindingRepository findingRepository;

    /**
     * Paged actionable items: <b>every compromise finding first</b>, then vulnerability alerts by
     * EPSS descending with unscored CVEs last.
     *
     * <h2>Why compromise findings form a tier rather than joining the EPSS sort</h2>
     *
     * <p>The roadmap's words are "compromise findings sort above everything", and that is not a
     * ranking preference — it is the only defensible answer. EPSS is the probability that a
     * vulnerability <em>will be</em> exploited in the next 30 days. A compromise finding says
     * malicious code is <em>already in your build</em>. There is no score to give the second that
     * makes it commensurable with the first, and inventing one (say, a synthetic EPSS of 1.0) would
     * be a lie that later phases would have to keep telling. So: two tiers, compromise first, each
     * internally sorted by its own meaningful ranking.
     *
     * <h2>How two queries page as one list</h2>
     *
     * <p>Because the tiers are strictly ordered, the union is a plain concatenation and offsets can
     * be computed arithmetically — no database {@code UNION} view, no materialised merge table, no
     * fetching both halves in full and sorting in memory:
     *
     * <ol>
     *   <li>count the compromise findings matching the filter ({@code C}) and the alerts ({@code V});
     *       {@code totalElements = C + V};</li>
     *   <li>the requested window is {@code [page*size, page*size+size)}. Whatever part of it falls
     *       below {@code C} is served from the finding query at that offset;</li>
     *   <li>whatever is left is served from the alert query at offset {@code max(0, page*size - C)}.</li>
     * </ol>
     *
     * <p>A page that straddles the boundary needs an alert offset that is not a multiple of the page
     * size, which is what {@link OffsetLimitRequest} exists for. Each half is fetched with a
     * {@code LIMIT} of at most {@code size}, so a page costs two explicit counts plus at most two
     * windowed selects however large either table gets — nothing is ever fetched and discarded.
     * ({@code findAll(Specification, Pageable)} may add a count of its own; Spring elides it when a
     * page comes back short.)
     *
     * <p>A filter that only one arm can satisfy skips the other arm's queries entirely — see
     * {@link ActionableFilter#includesVulnerabilities()}. That is not just an optimisation: a
     * {@code minCvss} filter must not report compromise findings in {@code totalElements} that it is
     * never going to return.
     */
    @Transactional(readOnly = true)
    public Page<ActionableItemResponse> findActionable(int page, int size, ActionableFilter filter) {
        Pageable pageable = PageRequest.of(page, size);

        Specification<CompromiseFinding> compromiseSpec = filter.includesCompromises()
                ? CompromiseService.specification(compromiseFilterFrom(filter))
                : null;
        Specification<VulnerabilityAlert> alertSpec = filter.includesVulnerabilities()
                ? specification(filter)
                : null;

        long compromiseTotal = compromiseSpec == null ? 0 : findingRepository.count(compromiseSpec);
        long alertTotal = alertSpec == null ? 0 : alertRepository.count(alertSpec);

        long offset = pageable.getOffset();
        List<ActionableItemResponse> content = new ArrayList<>(size);

        if (compromiseSpec != null && offset < compromiseTotal) {
            int take = (int) Math.min(size, compromiseTotal - offset);
            findingRepository.findAll(compromiseSpec, OffsetLimitRequest.of(offset, take))
                    .forEach(finding -> content.add(toRow(finding)));
        }

        int remaining = size - content.size();
        if (alertSpec != null && remaining > 0) {
            long alertOffset = Math.max(0, offset - compromiseTotal);
            if (alertOffset < alertTotal) {
                alertRepository.findAll(alertSpec, OffsetLimitRequest.of(alertOffset, remaining))
                        .forEach(alert -> content.add(toRow(alert)));
            }
        }

        return new PageImpl<>(content, pageable, compromiseTotal + alertTotal);
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
     *
     * <p>Phase 6 changes what this returns without changing the call: an asset shipping a malicious
     * package now shows that finding at the top of its own drill-down, because the union is built
     * into the shared query rather than bolted onto the Actionable Items screen.
     */
    @Transactional(readOnly = true)
    public Page<ActionableItemResponse> findActionableForAsset(int page, int size, UUID assetId) {
        return findActionable(page, size,
                new ActionableFilter(null, assetId, null, null, null, null, null, null, null, null));
    }

    /**
     * Project the union's filter onto the compromise arm.
     *
     * <p>Only the dimensions a finding actually has survive: scope and confidence. The
     * {@code includesCompromises()} guard has already established that no CVE-only dimension is set,
     * so nothing is being silently dropped here.
     */
    private static CompromiseFilter compromiseFilterFrom(ActionableFilter filter) {
        return new CompromiseFilter(null, filter.confidence(), filter.productId(), filter.assetId(),
                null, AlertLifecycleState.ACTIVE);
    }

    /**
     * Full detail for one <b>vulnerability</b> alert, or empty when the id is unknown.
     *
     * <p>Deliberately not a union. This response is the CVE record, every other component the same
     * CVE affects, the KEV entry, the EPSS entry and the CVE's references — a compromise finding has
     * none of those, so the only union shape available would be one where two thirds of the body is
     * null depending on an arm the caller already knows from the list row. A compromise id therefore
     * gets a 404 here and is fetched from {@code GET /compromise/{id}} instead; the list row's
     * {@code itemType} is what tells the client which to call.
     */
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
                ActionableItemType.VULNERABILITY,
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
                // The compromise arm, absent on a vulnerability row.
                null, null, null, null, null, null, null, null,
                alert.getCreatedAt());
    }

    /**
     * The other arm of the union: one compromise finding as an actionable row.
     *
     * <p>Note what is <em>shared</em> rather than nulled. {@code description} carries the finding's
     * summary, {@code baseSeverity} its fixed {@code CRITICAL}, and the whole component/scope block
     * is filled exactly as it is for an alert — because "which component, on which asset or in which
     * product" means the same thing whichever kind of finding it is, and the table renders those
     * columns identically. Only the genuinely CVE-shaped fields are null.
     *
     * @see ActionableItemResponse for the field-by-field contract
     */
    private static ActionableItemResponse toRow(CompromiseFinding finding) {
        CorrelatableComponent component = finding.getCorrelatableComponent();
        Product product = CompromiseService.productOf(finding.getComponent());
        Asset asset = CompromiseService.assetOf(finding.getAssetComponent());

        return new ActionableItemResponse(
                finding.getId(),
                ActionableItemType.COMPROMISE,
                null,
                summarize(finding.getSummary()),
                finding.getSeverity(),
                null, null, null,
                false,
                null, null, null, null, null, null, null,
                ActionableReason.COMPROMISE,
                product == null ? null : product.getId(),
                product == null ? null : product.getName(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                CompromiseService.componentIdOf(finding),
                component == null ? null : component.getName(),
                component == null ? null : component.getVersion(),
                component == null ? null : component.getPurl(),
                finding.getType(),
                finding.getConfidence(),
                finding.getSource(),
                finding.getIocId(),
                finding.getMatchedOn(),
                finding.getIocFirstSeen(),
                finding.getIocLastSeen(),
                finding.getIocConfidence(),
                finding.getCreatedAt());
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
