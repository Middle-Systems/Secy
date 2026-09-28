package net.jdesive.secy.service.finding;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.OffsetLimitRequest;
import net.jdesive.secy.model.finding.FindingFilter;
import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.model.finding.FindingResponse;
import net.jdesive.secy.model.finding.FindingTypeInfo;
import net.jdesive.secy.persistence.ActionItemFindingRepository;
import net.jdesive.secy.persistence.ActionItemRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.ActionItem;
import net.jdesive.secy.persistence.entity.ActionItemFinding;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Reads for {@code GET /findings} — the M1j read-model over the five existing finding tables, N-arm
 * tiered concatenation generalizing {@code ActionableService.findActionable}'s two-arm arithmetic
 * (see {@link Arm}). Deliberately parallel, new code — {@code ActionableService} is not touched or
 * refactored to share this.
 *
 * <p>Runs inside {@code @Transactional(readOnly = true)}: the vulnerability/compromise mapping walks
 * {@code component.sbom.product}/{@code assetComponent.asset} lazily via {@link FindingResolver}.
 *
 * <h2>Status derivation cost</h2>
 *
 * <p>After a page is fetched, its rows' links are batch-loaded, then those links' action items, then
 * <b>every</b> finding linked to those items (not just the ones on this page) — {@code forItem} needs
 * an item's complete finding set to compute reopen/remaining correctly. This is N+1-free per page:
 * one query per finding type touched, however large the page.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class FindingService {

    private final VulnerabilityAlertRepository alertRepository;
    private final CompromiseFindingRepository compromiseRepository;
    private final LifecycleDriftFindingRepository driftRepository;
    private final QuantumVulnerabilityFindingRepository quantumRepository;
    private final SbomQualityFindingRepository qualityRepository;
    private final ProductRepository productRepository;
    private final ActionItemFindingRepository actionItemFindingRepository;
    private final ActionItemRepository actionItemRepository;
    private final FindingResolver findingResolver;

    public Page<FindingResponse> list(int page, int size, FindingFilter filter) {
        Pageable pageable = PageRequest.of(page, size);
        List<Arm> arms = buildArms(filter);

        long[] counts = new long[arms.size()];
        long total = 0;
        for (int i = 0; i < arms.size(); i++) {
            counts[i] = arms.get(i).count();
            total += counts[i];
        }

        long offset = pageable.getOffset();
        List<ResolvedFinding> content = new ArrayList<>(size);
        long runningStart = 0;
        for (int i = 0; i < arms.size() && content.size() < size; i++) {
            long armCount = counts[i];
            long armEnd = runningStart + armCount;
            if (offset < armEnd) {
                long localOffset = Math.max(0, offset - runningStart);
                int take = (int) Math.min(size - content.size(), armCount - localOffset);
                if (take > 0) {
                    content.addAll(arms.get(i).fetch(localOffset, take));
                }
            }
            runningStart = armEnd;
        }

        List<FindingResponse> mapped = attachStatusAndMap(content, LocalDateTime.now());
        return new PageImpl<>(mapped, pageable, total);
    }

    public Optional<FindingResponse> detail(FindingType type, UUID id) {
        return findingResolver.resolve(type, id)
                .map(f -> attachStatusAndMap(List.of(f), LocalDateTime.now()).get(0));
    }

    public List<FindingTypeInfo> types() {
        return Arrays.stream(FindingType.values())
                .map(t -> new FindingTypeInfo(t, t.backedByTable(),
                        t.backedByTable() ? null : "Stub — no data source until M4 (provenance verification)"))
                .toList();
    }

    /* ------------------------------------------------------------------ */
    /* Arms                                                                */
    /* ------------------------------------------------------------------ */

    /**
     * One finding type's contribution to the concatenated union — {@code count()}/{@code fetch()}
     * mirror {@code ActionableService}'s per-arm count/windowed-select pair, generalized from two arms
     * fixed in code to N arms walked in a list, in the fixed tier order {@link #buildArms} builds.
     */
    private interface Arm {
        long count();

        List<ResolvedFinding> fetch(long offset, int limit);
    }

    private List<Arm> buildArms(FindingFilter filter) {
        List<Arm> arms = new ArrayList<>();
        if (filter.includesCompromise()) {
            arms.add(compromiseArm(filter));
        }
        if (filter.includesVulnerability()) {
            arms.add(vulnerabilityArm(filter));
        }
        if (filter.includesLifecycleDrift()) {
            arms.add(plainProductArm(driftRepository, filter, LifecycleDriftFinding.class, "lifecycleDriftFindingId",
                    (List<LifecycleDriftFinding> rows) -> mapWithProductNames(rows, LifecycleDriftFinding::getProductId,
                            (row, name) -> FindingResolver.from(row, name))));
        }
        if (filter.includesQuantumVulnerable()) {
            arms.add(plainProductArm(quantumRepository, filter, QuantumVulnerabilityFinding.class, "quantumVulnerabilityFindingId",
                    (List<QuantumVulnerabilityFinding> rows) -> mapWithProductNames(rows, QuantumVulnerabilityFinding::getProductId,
                            (row, name) -> FindingResolver.from(row, name))));
        }
        if (filter.includesSbomQuality()) {
            arms.add(plainProductArm(qualityRepository, filter, SbomQualityFinding.class, "sbomQualityFindingId",
                    (List<SbomQualityFinding> rows) -> mapWithProductNames(rows, SbomQualityFinding::getProductId,
                            (row, name) -> FindingResolver.from(row, name))));
        }
        return arms;
    }

    private Arm compromiseArm(FindingFilter filter) {
        Specification<CompromiseFinding> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (!filter.includeResolved()) {
                predicates.add(cb.equal(root.get("lifecycleState"), AlertLifecycleState.ACTIVE));
            }
            if (filter.productId() != null) {
                Join<CompromiseFinding, SBOMComponent> component = root.join("component", JoinType.INNER);
                Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            if (filter.assetId() != null) {
                Join<CompromiseFinding, AssetComponent> assetComponent = root.join("assetComponent", JoinType.INNER);
                predicates.add(cb.equal(assetComponent.get("asset").get("id"), filter.assetId()));
            }
            if (filter.linked() != null) {
                predicates.add(linkedPredicate(root, cb, query, "compromiseFindingId", filter.linked()));
            }
            if (!isCountQuery(query.getResultType())) {
                query.orderBy(cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        return new SpecArm<>(compromiseRepository, spec, rows -> rows.stream().map(FindingResolver::from).toList());
    }

    private Arm vulnerabilityArm(FindingFilter filter) {
        Specification<VulnerabilityAlert> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.isTrue(root.get("actionable")));
            if (!filter.includeResolved()) {
                predicates.add(cb.equal(root.get("lifecycleState"), AlertLifecycleState.ACTIVE));
            }
            if (filter.productId() != null) {
                Join<VulnerabilityAlert, SBOMComponent> component = root.join("component", JoinType.INNER);
                Join<SBOMComponent, SBOM> sbom = component.join("sbom", JoinType.INNER);
                predicates.add(cb.equal(sbom.get("product").get("id"), filter.productId()));
            }
            if (filter.assetId() != null) {
                Join<VulnerabilityAlert, AssetComponent> assetComponent = root.join("assetComponent", JoinType.INNER);
                predicates.add(cb.equal(assetComponent.get("asset").get("id"), filter.assetId()));
            }
            if (filter.linked() != null) {
                predicates.add(linkedPredicate(root, cb, query, "vulnerabilityAlertId", filter.linked()));
            }
            if (!isCountQuery(query.getResultType())) {
                Expression<Double> riskScore = cb.coalesce(root.<Double>get("riskScore"), -1.0d);
                Expression<Double> epss = cb.coalesce(root.<Double>get("epssScore"), -1.0d);
                query.orderBy(cb.desc(riskScore), cb.desc(epss), cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        return new SpecArm<>(alertRepository, spec, rows -> rows.stream().map(FindingResolver::from).toList());
    }

    /** Shared shape for {@code LIFECYCLE_DRIFT}/{@code QUANTUM_VULNERABLE}/{@code SBOM_QUALITY} — plain {@code productId}, no asset concept. */
    private <T> Arm plainProductArm(JpaSpecificationExecutor<T> repository, FindingFilter filter, Class<T> type,
                                     String linkColumn, Function<List<T>, List<ResolvedFinding>> mapper) {
        Specification<T> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (!filter.includeResolved()) {
                predicates.add(cb.equal(root.get("lifecycleState"), AlertLifecycleState.ACTIVE));
            }
            if (filter.productId() != null) {
                predicates.add(cb.equal(root.<UUID>get("productId"), filter.productId()));
            }
            if (filter.linked() != null) {
                predicates.add(linkedPredicate(root, cb, query, linkColumn, filter.linked()));
            }
            if (!isCountQuery(query.getResultType())) {
                query.orderBy(cb.desc(root.get("createdAt")), cb.asc(root.get("id")));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        return new SpecArm<>(repository, spec, mapper);
    }

    private static <T> Predicate linkedPredicate(Root<T> root, CriteriaBuilder cb, CriteriaQuery<?> query,
                                                  String linkColumn, boolean linked) {
        Subquery<Long> sub = query.subquery(Long.class);
        Root<ActionItemFinding> aif = sub.from(ActionItemFinding.class);
        sub.select(cb.literal(1L));
        sub.where(cb.equal(aif.get(linkColumn), root.<UUID>get("id")));
        return linked ? cb.exists(sub) : cb.not(cb.exists(sub));
    }

    private static boolean isCountQuery(Class<?> resultType) {
        return Long.class.equals(resultType) || long.class.equals(resultType);
    }

    /** One arm backed by a {@link JpaSpecificationExecutor}, mapped in one batch per {@code fetch()} call. */
    private record SpecArm<T>(JpaSpecificationExecutor<T> repository, Specification<T> spec,
                               Function<List<T>, List<ResolvedFinding>> mapper) implements Arm {
        @Override
        public long count() {
            return repository.count(spec);
        }

        @Override
        public List<ResolvedFinding> fetch(long offset, int limit) {
            List<T> rows = repository.findAll(spec, OffsetLimitRequest.of(offset, limit)).getContent();
            return mapper.apply(rows);
        }
    }

    private <T> List<ResolvedFinding> mapWithProductNames(List<T> rows, Function<T, UUID> productIdOf,
                                                            java.util.function.BiFunction<T, String, ResolvedFinding> mapper) {
        Set<UUID> productIds = rows.stream().map(productIdOf).filter(Objects::nonNull).collect(Collectors.toSet());
        Map<UUID, String> names = productIds.isEmpty() ? Map.of()
                : productRepository.findAllById(productIds).stream().collect(Collectors.toMap(Product::getId, Product::getName));
        return rows.stream().map(row -> mapper.apply(row, names.get(productIdOf.apply(row)))).toList();
    }

    /* ------------------------------------------------------------------ */
    /* Status derivation                                                  */
    /* ------------------------------------------------------------------ */

    private List<FindingResponse> attachStatusAndMap(List<ResolvedFinding> content, LocalDateTime now) {
        Map<FindingRef, ActionItemFinding> linksByRef = loadLinks(content);

        Set<UUID> itemIds = linksByRef.values().stream().map(ActionItemFinding::getActionItemId)
                .collect(Collectors.toCollection(HashSet::new));
        Map<UUID, ActionItem> itemsById = itemIds.isEmpty() ? Map.of()
                : actionItemRepository.findAllById(itemIds).stream().collect(Collectors.toMap(ActionItem::getId, i -> i));

        List<ActionItemFinding> allLinksForItems = itemIds.isEmpty() ? List.of()
                : actionItemFindingRepository.findAllByActionItemIdIn(new ArrayList<>(itemIds));
        Map<UUID, List<FindingRef>> refsByItem = new HashMap<>();
        for (ActionItemFinding link : allLinksForItems) {
            refsByItem.computeIfAbsent(link.getActionItemId(), k -> new ArrayList<>()).add(link.ref());
        }
        Set<FindingRef> allRefs = new HashSet<>();
        refsByItem.values().forEach(allRefs::addAll);
        Map<FindingRef, ResolvedFinding> resolvedByRef = findingResolver.resolveAll(allRefs);

        Map<UUID, RemediationStatusDeriver.ItemStatus> itemStatusById = new HashMap<>();
        for (UUID itemId : itemIds) {
            ActionItem item = itemsById.get(itemId);
            if (item == null) {
                continue;
            }
            List<ResolvedFinding> linkedFindings = refsByItem.getOrDefault(itemId, List.of()).stream()
                    .map(resolvedByRef::get).filter(Objects::nonNull).toList();
            RemediationStatusDeriver.ActionItemSnapshot snapshot = new RemediationStatusDeriver.ActionItemSnapshot(
                    item.getStatus(), item.getResolvedAt(), item.getRiskAcceptedUntil());
            itemStatusById.put(itemId, RemediationStatusDeriver.forItem(snapshot, linkedFindings, now));
        }

        return content.stream().map(f -> {
            FindingRef ref = new FindingRef(f.type(), f.id());
            ActionItemFinding link = linksByRef.get(ref);
            UUID actionItemId = link == null ? null : link.getActionItemId();
            RemediationStatusDeriver.ItemStatus itemStatus = actionItemId == null ? null : itemStatusById.get(actionItemId);
            RemediationStatusDeriver.FindingStatus status = RemediationStatusDeriver.forFinding(f, itemStatus, now);
            return toResponse(f, status, actionItemId);
        }).toList();
    }

    private Map<FindingRef, ActionItemFinding> loadLinks(List<ResolvedFinding> content) {
        Map<FindingRef, ActionItemFinding> links = new HashMap<>();

        List<UUID> vulnIds = idsOfType(content, FindingType.VULNERABILITY);
        if (!vulnIds.isEmpty()) {
            actionItemFindingRepository.findAllByVulnerabilityAlertIdIn(vulnIds)
                    .forEach(l -> links.put(new FindingRef(FindingType.VULNERABILITY, l.getVulnerabilityAlertId()), l));
        }
        List<UUID> compromiseIds = idsOfType(content, FindingType.COMPROMISE);
        if (!compromiseIds.isEmpty()) {
            actionItemFindingRepository.findAllByCompromiseFindingIdIn(compromiseIds)
                    .forEach(l -> links.put(new FindingRef(FindingType.COMPROMISE, l.getCompromiseFindingId()), l));
        }
        List<UUID> driftIds = idsOfType(content, FindingType.LIFECYCLE_DRIFT);
        if (!driftIds.isEmpty()) {
            actionItemFindingRepository.findAllByLifecycleDriftFindingIdIn(driftIds)
                    .forEach(l -> links.put(new FindingRef(FindingType.LIFECYCLE_DRIFT, l.getLifecycleDriftFindingId()), l));
        }
        List<UUID> quantumIds = idsOfType(content, FindingType.QUANTUM_VULNERABLE);
        if (!quantumIds.isEmpty()) {
            actionItemFindingRepository.findAllByQuantumVulnerabilityFindingIdIn(quantumIds)
                    .forEach(l -> links.put(new FindingRef(FindingType.QUANTUM_VULNERABLE, l.getQuantumVulnerabilityFindingId()), l));
        }
        List<UUID> qualityIds = idsOfType(content, FindingType.SBOM_QUALITY);
        if (!qualityIds.isEmpty()) {
            actionItemFindingRepository.findAllBySbomQualityFindingIdIn(qualityIds)
                    .forEach(l -> links.put(new FindingRef(FindingType.SBOM_QUALITY, l.getSbomQualityFindingId()), l));
        }
        return links;
    }

    private static List<UUID> idsOfType(List<ResolvedFinding> content, FindingType type) {
        return content.stream().filter(f -> f.type() == type).map(ResolvedFinding::id).toList();
    }

    private static FindingResponse toResponse(ResolvedFinding f, RemediationStatusDeriver.FindingStatus status, UUID actionItemId) {
        return new FindingResponse(
                f.id(), f.type(), f.title(), f.summary(), f.severity(),
                f.productId(), f.productName(), f.assetId(), f.assetName(),
                f.componentName(), f.componentVersion(), f.componentPurl(),
                f.lifecycleState(), f.createdAt(), f.lastSeenAt(), f.riskScore(),
                f.vexStatus(), f.vexJustification(), f.vexConflict(),
                f.triageState(), f.snoozedUntil(),
                status.status(), status.basis(), actionItemId, f.detailPath());
    }

}
