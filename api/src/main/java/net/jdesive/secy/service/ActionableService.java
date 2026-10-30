package net.jdesive.secy.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableDetailResponse;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.model.actionable.ActionableItemType;
import net.jdesive.secy.model.actionable.ActionableRank;
import net.jdesive.secy.model.actionable.OffsetLimitRequest;
import net.jdesive.secy.model.compromise.CompromiseFilter;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.model.scoring.RiskScoreBreakdown;
import net.jdesive.secy.model.scoring.RiskScoreResult;
import net.jdesive.secy.model.vex.VexExplanation;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.SBOMComponentDependencyRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.*;
import net.jdesive.secy.service.scoring.RiskScoreInputs;
import net.jdesive.secy.service.scoring.RiskScoringService;
import net.jdesive.secy.service.vex.VexResolutionService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
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

    /**
     * Sorts below every real EPSS/risk score, so "no data" lands at the bottom rather than the top of
     * a descending sort. Shared by both — M1i's {@code riskScore} coalesces to the same sentinel.
     */
    private static final double NO_SCORE = -1.0d;

    private final VulnerabilityAlertRepository alertRepository;

    private final CompromiseFindingRepository findingRepository;

    /** M1f: {@code GET /actionable/{id}}'s "which statements applied, and who won" block. */
    private final VexResolutionService vexResolutionService;

    /** M1i: {@code GET /actionable/{id}}'s risk-score breakdown block. */
    private final RiskScoringService riskScoringService;

    /** M1l: resolves {@code dependency.path} bom-refs back to a component's name/version. */
    private final SBOMComponentDependencyRepository dependencyRepository;

    private final ObjectMapper objectMapper;

    @PersistenceContext
    private EntityManager entityManager;

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
        return findActionable(page, size, filter, ActionableRank.EPSS);
    }

    /**
     * As {@link #findActionable(int, int, ActionableFilter)}, with {@code rankBy} choosing the
     * vulnerability tier's secondary sort key (M1i). {@link ActionableRank#EPSS} — the default,
     * unchanged since Phase 1 — sorts by EPSS descending with the M1i risk score as a tie-breaker
     * ahead of {@code createdAt}; {@link ActionableRank#SCORE} swaps the two. The compromise tier
     * always sorts first, by its own rules, in both modes.
     */
    @Transactional(readOnly = true)
    public Page<ActionableItemResponse> findActionable(int page, int size, ActionableFilter filter, ActionableRank rankBy) {
        Pageable pageable = PageRequest.of(page, size);

        Specification<CompromiseFinding> compromiseSpec = filter.includesCompromises()
                ? CompromiseService.specification(compromiseFilterFrom(filter)).and(triageSpecification(filter))
                : null;
        Specification<VulnerabilityAlert> alertSpec = filter.includesVulnerabilities()
                ? specification(filter, rankBy)
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
                new ActionableFilter(null, assetId, null, null, null, null, null, null, null, null, null, null, null));
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

    /**
     * Every {@code GET /actionable} vulnerability-tier filter clause, with <b>no ordering</b> —
     * shared by the paged query ({@link #specification(ActionableFilter, ActionableRank)}) and the
     * M1i rollup query ({@link #vulnerabilityRollup(ActionableFilter)}), which must count and max
     * over exactly the same population the list shows.
     */
    public static Predicate vulnerabilityPredicate(Root<VulnerabilityAlert> root, CriteriaBuilder cb, ActionableFilter filter) {
        List<Predicate> predicates = new ArrayList<>();

        // The two non-negotiable clauses: this endpoint is the funnel's output, and it shows
        // what is still true. An alert a re-scan no longer reproduces is kept (history, and any
        // triage done to it) but auto-resolved, and auto-resolved rows are not work.
        predicates.add(cb.isTrue(root.get("actionable")));
        predicates.add(cb.equal(root.get("lifecycleState"), AlertLifecycleState.ACTIVE));

        // Phase 7: the triage half of "what is still work" — see triagePredicate.
        predicates.add(triagePredicate(root, cb, filter));
        // M1f: the VEX half of "what is still work" — see vexPredicate. Composed the same way as
        // triagePredicate: a null filter hides what a VEX statement says is not actionable any
        // more, an explicit value is an exact match instead.
        predicates.add(vexPredicate(root, cb, filter));
        if (filter.vexConflict() != null) {
            predicates.add(cb.equal(root.get("vexConflict"), filter.vexConflict()));
        }

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
        if (filter.minScore() != null) {
            // M1i: unscored rows are excluded, same "unscored is not below the bar" rule as minCvss.
            predicates.add(cb.greaterThanOrEqualTo(root.get("riskScore"), filter.minScore()));
        }

        return cb.and(predicates.toArray(new Predicate[0]));
    }

    /**
     * {@link #vulnerabilityPredicate} plus the ordering (skipped for a count query), whose secondary
     * key {@code rankBy} chooses (M1i) — see {@link ActionableRank}.
     */
    private static Specification<VulnerabilityAlert> specification(ActionableFilter filter, ActionableRank rankBy) {
        return (root, query, cb) -> {
            Predicate predicate = vulnerabilityPredicate(root, cb, filter);

            // Spring Data only overwrites the ORDER BY when the Pageable carries a Sort, and the
            // service always passes an unsorted one; the count query must not get an ORDER BY at all.
            if (!isCountQuery(query.getResultType())) {
                Expression<Double> epss = cb.coalesce(root.<Double>get("epssScore"), NO_SCORE);
                Expression<Double> score = cb.coalesce(root.<Double>get("riskScore"), NO_SCORE);
                if (rankBy == ActionableRank.SCORE) {
                    query.orderBy(cb.desc(score), cb.desc(epss), cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
                } else {
                    query.orderBy(cb.desc(epss), cb.desc(score), cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
                }
            }

            return predicate;
        };
    }

    private static boolean isCountQuery(Class<?> resultType) {
        return Long.class.equals(resultType) || long.class.equals(resultType);
    }

    /* ------------------------------------------------------------------ */
    /* M1i — rollups                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * The vulnerability half of a risk rollup for one scope's filter — the maximum score, which alert
     * produced it, and how many of the population are (un)scored. {@code RiskRollupService} builds
     * {@code filter} with only {@code productId} or {@code assetId} set, so the population here is
     * exactly the default {@code GET /actionable} vulnerability listing for that scope.
     */
    public record RollupCounts(Double maxScore, UUID topFindingId, long findingCount, long unscoredFindingCount) {
    }

    @Transactional(readOnly = true)
    public RollupCounts vulnerabilityRollup(ActionableFilter filter) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Tuple> query = cb.createTupleQuery();
        Root<VulnerabilityAlert> root = query.from(VulnerabilityAlert.class);
        query.multiselect(
                cb.max(root.<Double>get("riskScore")),
                cb.count(root),
                cb.count(root.get("riskScore")));
        query.where(vulnerabilityPredicate(root, cb, filter));

        Tuple result = entityManager.createQuery(query).getSingleResult();
        Double maxScore = result.get(0, Double.class);
        long findingCount = result.get(1, Long.class);
        long scoredCount = result.get(2, Long.class);
        long unscoredFindingCount = findingCount - scoredCount;

        UUID topFindingId = null;
        if (maxScore != null) {
            List<VulnerabilityAlert> top = alertRepository
                    .findAll(specification(filter, ActionableRank.SCORE), OffsetLimitRequest.of(0, 1))
                    .getContent();
            if (!top.isEmpty()) {
                topFindingId = top.get(0).getId();
            }
        }

        return new RollupCounts(maxScore, topFindingId, findingCount, unscoredFindingCount);
    }

    /**
     * The compromise half of a risk rollup — counted separately, never folded into the score. Zero
     * when {@code filter} could not match any compromise row at all (see
     * {@link ActionableFilter#includesCompromises()}), same short-circuit as {@link #findActionable}.
     */
    @Transactional(readOnly = true)
    public long compromiseCount(ActionableFilter filter) {
        if (!filter.includesCompromises()) {
            return 0;
        }
        return findingRepository.count(CompromiseService.specification(compromiseFilterFrom(filter)).and(triageSpecification(filter)));
    }

    /* ------------------------------------------------------------------ */
    /* Phase 7 — triage filtering, shared by both arms                    */
    /* ------------------------------------------------------------------ */

    /**
     * The compromise arm's triage predicate, composed onto {@code CompromiseService.specification}
     * with {@link Specification#and}. Kept as a separately-composed specification rather than edited
     * into {@code CompromiseService.specification} itself, since that method is shared with the
     * dedicated {@code GET /compromise} endpoint — whose default listing is intentionally untouched by
     * Phase 7 triage state, only the {@code /actionable} union's default is.
     */
    private static Specification<CompromiseFinding> triageSpecification(ActionableFilter filter) {
        return (root, query, cb) -> triagePredicate(root, cb, filter);
    }

    /**
     * Whichever triage predicate {@link ActionableFilter#state()} asks for.
     *
     * <p>Null (the default): hide what is not work any more — {@code RESOLVED}, {@code FALSE_POSITIVE},
     * or a {@code SNOOZED} row whose snooze has not yet expired. A snooze past its expiry reappears
     * automatically, with no cron job: the same {@code snoozedUntil <= now} half of this predicate
     * runs on every request.
     *
     * <p>A real value: exact match on that {@link TriageState} instead of the default hide-behavior.
     */
    private static <T> Predicate triagePredicate(Root<T> root, CriteriaBuilder cb, ActionableFilter filter) {
        if (filter.state() != null) {
            TriageState state = TriageState.valueOf(filter.state().toUpperCase(Locale.ROOT));
            return cb.equal(root.get("triageState"), state);
        }
        Predicate resolved = cb.equal(root.get("triageState"), TriageState.RESOLVED);
        Predicate falsePositive = cb.equal(root.get("triageState"), TriageState.FALSE_POSITIVE);
        Predicate stillSnoozed = cb.and(
                cb.equal(root.get("triageState"), TriageState.SNOOZED),
                cb.greaterThan(root.<LocalDateTime>get("snoozedUntil"), LocalDateTime.now()));
        return cb.not(cb.or(resolved, falsePositive, stillSnoozed));
    }

    /**
     * M1f's VEX half of "what is still work", the same shape as {@link #triagePredicate}. Null (the
     * default): hide {@code NOT_AFFECTED} and {@code FIXED} — both are "not work" — while
     * {@code AFFECTED}/{@code UNDER_INVESTIGATION} (and no VEX statement at all, i.e. {@code null})
     * stay visible. A real value: exact match instead. No existing fixture has VEX data, so
     * {@code vexStatus} is null on every row before M1f and this predicate is a no-op for every
     * existing test.
     */
    private static <T> Predicate vexPredicate(Root<T> root, CriteriaBuilder cb, ActionableFilter filter) {
        if (filter.vexStatus() != null) {
            return cb.equal(root.get("vexStatus"), filter.vexStatus());
        }
        return cb.or(
                cb.isNull(root.<VexStatus>get("vexStatus")),
                cb.not(root.<VexStatus>get("vexStatus").in(VexStatus.NOT_AFFECTED, VexStatus.FIXED)));
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
                RiskScoreInputs.isKevListed(alert),
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
                alert.getCreatedAt(),
                alert.getTriageState(),
                alert.getAssignee() == null ? null : alert.getAssignee().getId(),
                alert.getAssignee() == null ? null : assigneeName(alert.getAssignee()),
                alert.getSnoozedUntil(),
                alert.getVexStatus(),
                alert.getVexJustification(),
                alert.isVexConflict(),
                alert.getVexStatementId(),
                alert.getRiskScore());
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
                finding.getCreatedAt(),
                finding.getTriageState(),
                finding.getAssignee() == null ? null : finding.getAssignee().getId(),
                finding.getAssignee() == null ? null : assigneeName(finding.getAssignee()),
                finding.getSnoozedUntil(),
                null, null, false, null,
                // M1i: compromise findings are never scored -- see the class Javadoc.
                null);
    }

    /** Falls back to email when a user has set no display name — the same rule {@code TriageService} uses. */
    private static String assigneeName(User user) {
        return user.getDisplayName() != null ? user.getDisplayName() : user.getEmail();
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
                toReferences(cve),
                toVex(alert),
                alert.getRiskScore(),
                toRiskBreakdown(alert),
                toDependencyContext(alert));
    }

    /**
     * M1l: null for an asset alert ({@code alert.component == null} — {@code AssetComponent} has no
     * dependency graph); otherwise the component's stored depth (null column read as UNKNOWN,
     * mirroring {@code RiskScoreInputs.dependencyDepthOf}), distance, and its stored shortest path
     * resolved back to component names/versions. A null/absent path reads as an empty list, not a
     * null one, so the UI never has to tell "no path" apart from "not computed".
     */
    private ActionableDetailResponse.DependencyContext toDependencyContext(VulnerabilityAlert alert) {
        SBOMComponent component = alert.getComponent();
        if (component == null || component.getSbom() == null) {
            return null;
        }
        DependencyDepth depth = component.getDependencyDepth() == null
                ? DependencyDepth.UNKNOWN : component.getDependencyDepth();
        List<String> refs = parsePath(component.getDependencyPath());
        SBOMComponent root = component.getSbom().getComponent();
        List<ActionableDetailResponse.PathHop> hops =
                toPathHops(component.getSbom().getId(), refs, root != null ? root.getId() : null);
        return new ActionableDetailResponse.DependencyContext(depth, component.getDependencyDistance(), hops);
    }

    private List<String> parsePath(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<List<String>>() {
            });
        } catch (JsonProcessingException e) {
            // A display-only field -- degrade to "no path" rather than failing the whole detail read.
            return List.of();
        }
    }

    /**
     * Resolves each bom-ref against {@code sbomId}'s components. A ref with no match, or 2+
     * matches where none is the SBOM's own root, reads as unresolved. 2+ matches where one IS the
     * root resolves to the root — the same "root wins over a duplicate" tie-break
     * {@code SBOMService.persistDependencyEdges} applies at ingest time, so a document that repeats
     * its root's bom-ref inside {@code components[]} resolves identically through both paths rather
     * than resolving cleanly at ingest and unresolved here.
     */
    private List<ActionableDetailResponse.PathHop> toPathHops(UUID sbomId, List<String> refs, UUID rootComponentId) {
        if (refs.isEmpty()) {
            return List.of();
        }
        List<SBOMComponent> matches = dependencyRepository.findComponentsBySbomIdAndBomRefIn(sbomId, refs);
        java.util.Map<String, List<SBOMComponent>> byRef = matches.stream()
                .collect(java.util.stream.Collectors.groupingBy(SBOMComponent::getBomRef));
        List<ActionableDetailResponse.PathHop> hops = new ArrayList<>(refs.size());
        for (String ref : refs) {
            SBOMComponent resolved = resolveOne(byRef.get(ref), rootComponentId);
            if (resolved == null) {
                hops.add(new ActionableDetailResponse.PathHop(ref, null, null, null));
            } else {
                hops.add(new ActionableDetailResponse.PathHop(ref, resolved.getId(), resolved.getName(), resolved.getVersion()));
            }
        }
        return hops;
    }

    private static SBOMComponent resolveOne(List<SBOMComponent> candidates, UUID rootComponentId) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        if (candidates.size() == 1) {
            return candidates.get(0);
        }
        if (rootComponentId != null) {
            for (SBOMComponent c : candidates) {
                if (rootComponentId.equals(c.getId())) {
                    return c;
                }
            }
        }
        return null;
    }

    /** M1i: the alert's stored risk score/model/scoredAt alongside a freshly recomputed breakdown. */
    private RiskScoreBreakdown toRiskBreakdown(VulnerabilityAlert alert) {
        RiskScoreResult fresh = riskScoringService.explain(alert);
        boolean current = Objects.equals(alert.getRiskScore(), fresh.score())
                && Objects.equals(alert.getRiskScoreModel(), fresh.model());
        return new RiskScoreBreakdown(
                alert.getRiskScore(),
                alert.getRiskScoreModel(),
                alert.getRiskScoredAt(),
                fresh.score(),
                fresh.model(),
                current,
                fresh.factors());
    }

    /** M1f: the alert's stored VEX snapshot, plus every applicable statement from {@code explain}. */
    private ActionableDetailResponse.Vex toVex(VulnerabilityAlert alert) {
        VexExplanation explanation = vexResolutionService.explain(alert);
        List<ActionableDetailResponse.AppliedVexStatement> statements = explanation.statements().stream()
                .map(applied -> {
                    VexStatement s = applied.statement();
                    return new ActionableDetailResponse.AppliedVexStatement(
                            s.getId(), s.getDocumentId(), s.getFormat(), s.getOrigin(), s.getAuthor(),
                            s.getStatus(), s.getSourceStatus(), s.getJustification(), s.getSourceJustification(),
                            s.getImpactStatement(), s.getActionStatement(), s.getProductRef(), s.getTargetPurl(),
                            s.getMatchVersion(), s.getStatementTimestamp(), applied.role());
                })
                .toList();
        return new ActionableDetailResponse.Vex(
                alert.getVexStatus(), alert.getVexJustification(), alert.isVexConflict(), alert.getVexStatementId(),
                explanation.policy(), alert.getVexUpdatedAt(), statements);
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
