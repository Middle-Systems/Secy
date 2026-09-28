package net.jdesive.secy.service.actionitem;

import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.AddCommentRequest;
import net.jdesive.secy.model.actionitem.ActionItemDetailResponse;
import net.jdesive.secy.model.actionitem.ActionItemEventResponse;
import net.jdesive.secy.model.actionitem.ActionItemPatchRequest;
import net.jdesive.secy.model.actionitem.ActionItemResponse;
import net.jdesive.secy.model.actionitem.ActionItemScore;
import net.jdesive.secy.model.actionitem.AttachFindingsRequest;
import net.jdesive.secy.model.actionitem.CreateActionItemRequest;
import net.jdesive.secy.model.actionitem.RiskAcceptance;
import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.model.finding.FindingResponse;
import net.jdesive.secy.persistence.ActionItemEventRepository;
import net.jdesive.secy.persistence.ActionItemFindingRepository;
import net.jdesive.secy.persistence.ActionItemRepository;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.entity.ActionItem;
import net.jdesive.secy.persistence.entity.ActionItemEvent;
import net.jdesive.secy.persistence.entity.ActionItemEventType;
import net.jdesive.secy.persistence.entity.ActionItemFinding;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.service.finding.FindingResolver;
import net.jdesive.secy.service.finding.RemediationStatusDeriver;
import net.jdesive.secy.service.finding.ResolvedFinding;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * All {@code ActionItem} mutation and read logic (M1j — ROADMAP.md's "Finding &amp; Action-item
 * model" §3/§4/§5/§6). See the plan's §6 "Implementation note": effective status is derived, not
 * stored, so {@link #list} fetches candidates by indexed columns (product/asset/assignee) and then
 * derives, filters, sorts and pages <b>in memory</b> — acceptable because action items are
 * human-created, hundreds not millions per tenant. A future milestone may add a materialized
 * {@code effective_status} column if volume ever demands it.
 */
@Service
@RequiredArgsConstructor
@Transactional
public class ActionItemService {

    private final ActionItemRepository actionItemRepository;
    private final ActionItemFindingRepository actionItemFindingRepository;
    private final ActionItemEventRepository actionItemEventRepository;
    private final AppUserRepository appUserRepository;
    private final TenantMembershipRepository tenantMembershipRepository;
    private final ProductRepository productRepository;
    private final AssetRepository assetRepository;
    private final FindingResolver findingResolver;

    /* ------------------------------------------------------------------ */
    /* Create                                                              */
    /* ------------------------------------------------------------------ */

    public ActionItemDetailResponse create(CreateActionItemRequest request, User actingUser) {
        List<FindingRef> refs = request.findings();
        Map<FindingRef, ResolvedFinding> resolved = resolveAndValidateRefs(refs);

        Scope scope = deriveScope(resolved.values());

        for (FindingRef ref : refs) {
            checkNotAlreadyLinked(ref);
        }

        ActionItem item = new ActionItem();
        item.setTitle(request.title());
        item.setDescription(request.description());
        item.setProductId(scope.productId());
        item.setAssetId(scope.assetId());
        item.setStatus(RemediationStatus.OPEN);
        item.setCreatedById(actingUser.getId());
        item.setTenantId(scope.tenantId());
        item = actionItemRepository.save(item);

        appendEvent(item, ActionItemEventType.CREATED, null, null, null, null, null, null, null, actingUser);

        LocalDateTime now = LocalDateTime.now();
        for (FindingRef ref : refs) {
            ActionItemFinding link = new ActionItemFinding();
            link.setTenantId(item.getTenantId());
            link.setActionItemId(item.getId());
            link.setFinding(ref.type(), ref.id());
            link.setAttachedById(actingUser.getId());
            link.setAttachedAt(now);
            actionItemFindingRepository.save(link);
            appendEvent(item, ActionItemEventType.FINDING_ATTACHED, null, null, null,
                    ref.type(), ref.id(), null, null, actingUser);
        }

        if (request.assigneeUserId() != null) {
            User assignee = validateAssignee(request.assigneeUserId(), item.getTenantId());
            item.setAssigneeId(assignee.getId());
            actionItemRepository.save(item);
            appendEvent(item, ActionItemEventType.ASSIGNED, null, null, null, null, null,
                    assignee.getId(), null, actingUser);
        }

        return toDetail(item);
    }

    /* ------------------------------------------------------------------ */
    /* Read                                                                */
    /* ------------------------------------------------------------------ */

    @Transactional(readOnly = true)
    public Page<ActionItemResponse> list(int page, int size, UUID productId, UUID assetId,
                                          UUID assigneeUserId, RemediationStatus status) {
        Specification<ActionItem> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (productId != null) {
                predicates.add(cb.equal(root.get("productId"), productId));
            }
            if (assetId != null) {
                predicates.add(cb.equal(root.get("assetId"), assetId));
            }
            if (assigneeUserId != null) {
                predicates.add(cb.equal(root.get("assigneeId"), assigneeUserId));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        List<ActionItem> candidates = actionItemRepository.findAll(spec);

        List<ActionItemResponse> responses = toResponses(candidates);

        List<ActionItemResponse> filtered = responses.stream()
                .filter(r -> status == null
                        ? !(r.status() == RemediationStatus.RESOLVED || r.status() == RemediationStatus.NOT_AFFECTED
                                || r.status() == RemediationStatus.RISK_ACCEPTED)
                        : r.status() == status)
                .sorted(LIST_ORDER)
                .toList();

        Pageable pageable = PageRequest.of(page, size);
        int from = Math.min((int) pageable.getOffset(), filtered.size());
        int to = Math.min(from + size, filtered.size());
        return new PageImpl<>(filtered.subList(from, to), pageable, filtered.size());
    }

    private static final Comparator<ActionItemResponse> LIST_ORDER = Comparator
            .<ActionItemResponse>comparingInt(r -> switch (r.status()) {
                case OPEN -> 0;
                case IN_PROGRESS -> 1;
                default -> 2;
            })
            .thenComparing(r -> r.score() == null || r.score().riskScore() == null ? Double.NEGATIVE_INFINITY : r.score().riskScore(),
                    Comparator.reverseOrder())
            .thenComparing(ActionItemResponse::updatedAt, Comparator.reverseOrder())
            .thenComparing(ActionItemResponse::id);

    @Transactional(readOnly = true)
    public Optional<ActionItemDetailResponse> detail(UUID id) {
        return actionItemRepository.findById(id).map(this::toDetail);
    }

    @Transactional(readOnly = true)
    public List<ActionItemEventResponse> history(UUID id) {
        ActionItem item = requireItem(id);
        List<ActionItemEvent> events = actionItemEventRepository.findAllByActionItemIdOrderByCreatedAtAsc(item.getId());
        Map<UUID, String> names = userNames(events.stream().map(ActionItemEvent::getChangedById).collect(Collectors.toSet()));
        return events.stream().map(e -> toEventResponse(e, names)).toList();
    }

    /* ------------------------------------------------------------------ */
    /* Patch                                                               */
    /* ------------------------------------------------------------------ */

    public ActionItemDetailResponse patch(UUID id, ActionItemPatchRequest request, User actingUser) {
        ActionItem item = requireItem(id);

        if (request.status() == RemediationStatus.NOT_AFFECTED) {
            throw new InvalidActionItemException("NOT_AFFECTED is derived from VEX, not settable; upload a VEX statement");
        }
        boolean hasRiskFields = request.riskAcceptedUntil() != null || request.riskAcceptanceJustification() != null
                || request.riskApprovedByUserId() != null || request.riskApprovalNote() != null;
        if (hasRiskFields && request.status() != RemediationStatus.RISK_ACCEPTED) {
            throw new InvalidActionItemException("risk acceptance fields require status=RISK_ACCEPTED in the same request");
        }
        if (request.assigneeUserId() != null && Boolean.TRUE.equals(request.unassign())) {
            throw new InvalidActionItemException("assigneeUserId and unassign can't both be set");
        }

        RemediationStatusDeriver.ItemStatus before = computeStatus(item);

        if (request.title() != null) {
            item.setTitle(request.title());
        }
        if (request.description() != null) {
            item.setDescription(request.description());
        }

        boolean stateChanged = false;
        RemediationStatus requestedStatus = request.status();
        if (requestedStatus != null) {
            stateChanged = requestedStatus == RemediationStatus.RISK_ACCEPTED || requestedStatus != before.status();

            RemediationStatus previousStored = item.getStatus();

            if (requestedStatus == RemediationStatus.RISK_ACCEPTED) {
                if (request.riskAcceptedUntil() == null || !request.riskAcceptedUntil().isAfter(LocalDateTime.now())) {
                    throw new InvalidActionItemException("riskAcceptedUntil is required and must be strictly in the future");
                }
                if (request.riskAcceptanceJustification() == null || request.riskAcceptanceJustification().isBlank()) {
                    throw new InvalidActionItemException("riskAcceptanceJustification is required and must not be blank");
                }
                UUID approvedBy = null;
                if (request.riskApprovedByUserId() != null) {
                    approvedBy = validateAssignee(request.riskApprovedByUserId(), item.getTenantId()).getId();
                }
                item.setRiskAcceptedUntil(request.riskAcceptedUntil());
                item.setRiskAcceptedAt(LocalDateTime.now());
                item.setRiskAcceptedById(actingUser.getId());
                item.setRiskAcceptanceJustification(request.riskAcceptanceJustification());
                item.setRiskApprovedById(approvedBy);
                item.setRiskApprovalNote(request.riskApprovalNote());
            } else if (previousStored == RemediationStatus.RISK_ACCEPTED) {
                clearRiskAcceptance(item);
            }

            if (requestedStatus == RemediationStatus.RESOLVED) {
                item.setResolvedAt(LocalDateTime.now());
            } else if (previousStored == RemediationStatus.RESOLVED) {
                item.setResolvedAt(null);
            }

            item.setStatus(requestedStatus);
        }

        actionItemRepository.save(item);

        if (stateChanged) {
            // before.derivation() is non-null exactly when the effective status differed from the
            // stored one before this change -- that is how a derived reopen/expiry enters history.
            appendEvent(item, ActionItemEventType.STATUS_CHANGED, before.status(), requestedStatus,
                    before.derivation(), null, null, null, null, actingUser, request.comment());
        } else if (request.title() != null || request.description() != null) {
            appendEvent(item, ActionItemEventType.EDITED, null, null, null, null, null, null, null,
                    actingUser, request.comment());
        } else if (request.comment() != null && !request.comment().isBlank()) {
            appendEvent(item, ActionItemEventType.COMMENTED, null, null, null, null, null, null, null,
                    actingUser, request.comment());
        }

        if (Boolean.TRUE.equals(request.unassign())) {
            item.setAssigneeId(null);
            actionItemRepository.save(item);
            appendEvent(item, ActionItemEventType.UNASSIGNED, null, null, null, null, null, null, null, actingUser);
        } else if (request.assigneeUserId() != null) {
            User assignee = validateAssignee(request.assigneeUserId(), item.getTenantId());
            item.setAssigneeId(assignee.getId());
            actionItemRepository.save(item);
            appendEvent(item, ActionItemEventType.ASSIGNED, null, null, null, null, null, assignee.getId(), null, actingUser);
        }

        return toDetail(item);
    }

    /* ------------------------------------------------------------------ */
    /* Findings                                                            */
    /* ------------------------------------------------------------------ */

    public ActionItemDetailResponse attachFindings(UUID id, AttachFindingsRequest request, User actingUser) {
        ActionItem item = requireItem(id);
        RemediationStatusDeriver.ItemStatus current = computeStatus(item);
        if (current.status() == RemediationStatus.RISK_ACCEPTED || current.status() == RemediationStatus.NOT_AFFECTED
                || current.status() == RemediationStatus.RESOLVED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "reopen or move to In progress first");
        }

        Map<FindingRef, ResolvedFinding> resolved = resolveAndValidateRefs(request.findings());
        for (ResolvedFinding f : resolved.values()) {
            boolean matchesProduct = item.getProductId() != null && item.getProductId().equals(f.productId());
            boolean matchesAsset = item.getAssetId() != null && item.getAssetId().equals(f.assetId());
            if (!matchesProduct && !matchesAsset) {
                throw new InvalidActionItemException("finding " + f.type() + "/" + f.id()
                        + " does not share this action item's scope");
            }
        }
        for (FindingRef ref : request.findings()) {
            checkNotAlreadyLinked(ref);
        }

        LocalDateTime now = LocalDateTime.now();
        for (FindingRef ref : request.findings()) {
            ActionItemFinding link = new ActionItemFinding();
            link.setTenantId(item.getTenantId());
            link.setActionItemId(item.getId());
            link.setFinding(ref.type(), ref.id());
            link.setAttachedById(actingUser.getId());
            link.setAttachedAt(now);
            actionItemFindingRepository.save(link);
            appendEvent(item, ActionItemEventType.FINDING_ATTACHED, null, null, null,
                    ref.type(), ref.id(), null, null, actingUser);
        }

        return toDetail(item);
    }

    public void detachFinding(UUID id, FindingType type, UUID findingId) {
        ActionItem item = requireItem(id);
        ActionItemFinding link = findLink(type, findingId)
                .filter(l -> l.getActionItemId().equals(item.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "finding is not attached to this action item"));
        actionItemFindingRepository.delete(link);
        appendEvent(item, ActionItemEventType.FINDING_DETACHED, null, null, null, type, findingId, null, null, null);
    }

    public ActionItemEventResponse addComment(UUID id, AddCommentRequest request, User actingUser) {
        ActionItem item = requireItem(id);
        ActionItemEvent event = appendEvent(item, ActionItemEventType.COMMENTED, null, null, null, null, null,
                null, null, actingUser, request.comment());
        return toEventResponse(event, userNames(Set.of(actingUser.getId())));
    }

    /* ------------------------------------------------------------------ */
    /* Scope / validation                                                  */
    /* ------------------------------------------------------------------ */

    private record Scope(UUID tenantId, UUID productId, UUID assetId) {
    }

    /**
     * Every finding must share one identical {@code (productId, assetId)} scope — narrower than
     * "upgrades are grouped": a cross-product campaign is N action items, one per product.
     */
    private Scope deriveScope(Collection<ResolvedFinding> findings) {
        UUID tenantId = null;
        UUID productId = null;
        UUID assetId = null;
        boolean first = true;
        for (ResolvedFinding f : findings) {
            UUID fProduct = f.productId();
            UUID fAsset = f.assetId();
            if (fProduct == null && fAsset == null) {
                throw new InvalidActionItemException("finding " + f.type() + "/" + f.id() + " has no product or asset scope");
            }
            if (first) {
                tenantId = f.tenantId();
                productId = fProduct;
                assetId = fAsset;
                first = false;
            } else {
                if (!Objects.equals(productId, fProduct) || !Objects.equals(assetId, fAsset)) {
                    throw new InvalidActionItemException("findings span more than one product/asset scope — "
                            + "attach them to separate action items, one per scope");
                }
                if (!Objects.equals(tenantId, f.tenantId())) {
                    throw new InvalidActionItemException("findings span more than one tenant");
                }
            }
        }
        return new Scope(tenantId, productId, assetId);
    }

    private Map<FindingRef, ResolvedFinding> resolveAndValidateRefs(List<FindingRef> refs) {
        if (refs == null || refs.isEmpty()) {
            throw new InvalidActionItemException("findings must not be empty");
        }
        List<FindingRef> provenance = refs.stream().filter(r -> r.type() == FindingType.PROVENANCE).toList();
        if (!provenance.isEmpty()) {
            throw new InvalidActionItemException("PROVENANCE has no backing finding table yet");
        }
        Map<FindingRef, ResolvedFinding> resolved = findingResolver.resolveAll(refs);
        List<FindingRef> missing = refs.stream().filter(r -> !resolved.containsKey(r)).toList();
        if (!missing.isEmpty()) {
            throw new InvalidActionItemException("unknown finding(s): " + missing.stream()
                    .map(r -> r.type() + "/" + r.id()).collect(Collectors.joining(", ")));
        }
        return resolved;
    }

    private void checkNotAlreadyLinked(FindingRef ref) {
        Optional<ActionItemFinding> existing = findLink(ref.type(), ref.id());
        if (existing.isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "finding " + ref.type() + "/" + ref.id()
                    + " is already linked to action item " + existing.get().getActionItemId());
        }
    }

    private Optional<ActionItemFinding> findLink(FindingType type, UUID findingId) {
        return switch (type) {
            case VULNERABILITY -> actionItemFindingRepository.findByVulnerabilityAlertId(findingId);
            case COMPROMISE -> actionItemFindingRepository.findByCompromiseFindingId(findingId);
            case LIFECYCLE_DRIFT -> actionItemFindingRepository.findByLifecycleDriftFindingId(findingId);
            case QUANTUM_VULNERABLE -> actionItemFindingRepository.findByQuantumVulnerabilityFindingId(findingId);
            case SBOM_QUALITY -> actionItemFindingRepository.findBySbomQualityFindingId(findingId);
            case PROVENANCE -> Optional.empty();
        };
    }

    private User validateAssignee(UUID userId, UUID tenantId) {
        User user = appUserRepository.findById(userId)
                .orElseThrow(() -> new InvalidActionItemException("no user found with id " + userId));
        if (!user.isEnabled()) {
            throw new InvalidActionItemException("user " + user.getEmail() + " is disabled");
        }
        if (!tenantMembershipRepository.existsByTenantIdAndUserId(tenantId, user.getId())) {
            throw new InvalidActionItemException("user " + user.getEmail() + " is not a member of this action item's tenant");
        }
        return user;
    }

    private void clearRiskAcceptance(ActionItem item) {
        item.setRiskAcceptedUntil(null);
        item.setRiskAcceptedAt(null);
        item.setRiskAcceptedById(null);
        item.setRiskAcceptanceJustification(null);
        item.setRiskApprovedById(null);
        item.setRiskApprovalNote(null);
    }

    private ActionItem requireItem(UUID id) {
        return actionItemRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Action item not found"));
    }

    /* ------------------------------------------------------------------ */
    /* Status computation                                                  */
    /* ------------------------------------------------------------------ */

    private RemediationStatusDeriver.ItemStatus computeStatus(ActionItem item) {
        List<ActionItemFinding> links = actionItemFindingRepository.findAllByActionItemId(item.getId());
        List<FindingRef> refs = links.stream().map(ActionItemFinding::ref).toList();
        Map<FindingRef, ResolvedFinding> resolved = findingResolver.resolveAll(refs);
        List<ResolvedFinding> linked = refs.stream().map(resolved::get).filter(Objects::nonNull).toList();
        RemediationStatusDeriver.ActionItemSnapshot snapshot = new RemediationStatusDeriver.ActionItemSnapshot(
                item.getStatus(), item.getResolvedAt(), item.getRiskAcceptedUntil());
        return RemediationStatusDeriver.forItem(snapshot, linked, LocalDateTime.now());
    }

    /* ------------------------------------------------------------------ */
    /* Response assembly                                                   */
    /* ------------------------------------------------------------------ */

    private ActionItemDetailResponse toDetail(ActionItem item) {
        List<ActionItemFinding> links = actionItemFindingRepository.findAllByActionItemId(item.getId());
        List<FindingRef> refs = links.stream().map(ActionItemFinding::ref).toList();
        Map<FindingRef, ResolvedFinding> resolved = findingResolver.resolveAll(refs);
        List<ResolvedFinding> linked = refs.stream().map(resolved::get).filter(Objects::nonNull).toList();

        RemediationStatusDeriver.ActionItemSnapshot snapshot = new RemediationStatusDeriver.ActionItemSnapshot(
                item.getStatus(), item.getResolvedAt(), item.getRiskAcceptedUntil());
        LocalDateTime now = LocalDateTime.now();
        RemediationStatusDeriver.ItemStatus itemStatus = RemediationStatusDeriver.forItem(snapshot, linked, now);

        Set<UUID> userIds = new HashSet<>();
        if (item.getAssigneeId() != null) {
            userIds.add(item.getAssigneeId());
        }
        if (item.getRiskAcceptedById() != null) {
            userIds.add(item.getRiskAcceptedById());
        }
        if (item.getRiskApprovedById() != null) {
            userIds.add(item.getRiskApprovedById());
        }
        Map<UUID, String> names = userNames(userIds);

        List<FindingResponse> findingResponses = linked.stream().map(f -> {
            RemediationStatusDeriver.FindingStatus fs = RemediationStatusDeriver.forFinding(f, itemStatus, now);
            return new FindingResponse(f.id(), f.type(), f.title(), f.summary(), f.severity(),
                    f.productId(), f.productName(), f.assetId(), f.assetName(),
                    f.componentName(), f.componentVersion(), f.componentPurl(),
                    f.lifecycleState(), f.createdAt(), f.lastSeenAt(), f.riskScore(),
                    f.vexStatus(), f.vexJustification(), f.vexConflict(),
                    f.triageState(), f.snoozedUntil(), fs.status(), fs.basis(), item.getId(), f.detailPath());
        }).toList();

        String productName = item.getProductId() == null ? null
                : productRepository.findById(item.getProductId()).map(Product::getName).orElse(null);
        String assetName = item.getAssetId() == null ? null
                : assetRepository.findById(item.getAssetId()).map(Asset::getName).orElse(null);

        return new ActionItemDetailResponse(
                item.getId(), item.getTitle(), item.getDescription(),
                item.getProductId(), productName, item.getAssetId(), assetName,
                itemStatus.status(), item.getStatus(), itemStatus.derivation(),
                itemStatus.reopened(), itemStatus.reopenedFindings(),
                itemStatus.riskAcceptanceExpired(), itemStatus.awaitingVerification(), itemStatus.fixVerified(),
                item.getAssigneeId(), item.getAssigneeId() == null ? null : names.get(item.getAssigneeId()),
                linked.size(), remainingCount(linked), countsByType(links),
                score(linked),
                item.getStatus() == RemediationStatus.RISK_ACCEPTED ? riskAcceptance(item, names) : null,
                findingResponses,
                item.getCreatedAt(), item.getCreatedById(), item.getUpdatedAt(), item.getResolvedAt());
    }

    private List<ActionItemResponse> toResponses(List<ActionItem> items) {
        if (items.isEmpty()) {
            return List.of();
        }
        List<UUID> itemIds = items.stream().map(ActionItem::getId).toList();
        List<ActionItemFinding> allLinks = actionItemFindingRepository.findAllByActionItemIdIn(itemIds);
        Map<UUID, List<ActionItemFinding>> linksByItem = allLinks.stream()
                .collect(Collectors.groupingBy(ActionItemFinding::getActionItemId));
        Set<FindingRef> allRefs = allLinks.stream().map(ActionItemFinding::ref).collect(Collectors.toSet());
        Map<FindingRef, ResolvedFinding> resolved = findingResolver.resolveAll(allRefs);

        Set<UUID> productIds = items.stream().map(ActionItem::getProductId).filter(Objects::nonNull).collect(Collectors.toSet());
        Set<UUID> assetIds = items.stream().map(ActionItem::getAssetId).filter(Objects::nonNull).collect(Collectors.toSet());
        Map<UUID, String> productNames = productIds.isEmpty() ? Map.of()
                : productRepository.findAllById(productIds).stream().collect(Collectors.toMap(Product::getId, Product::getName));
        Map<UUID, String> assetNames = assetIds.isEmpty() ? Map.of()
                : assetRepository.findAllById(assetIds).stream().collect(Collectors.toMap(Asset::getId, Asset::getName));

        Set<UUID> userIds = new HashSet<>();
        for (ActionItem item : items) {
            if (item.getAssigneeId() != null) {
                userIds.add(item.getAssigneeId());
            }
            if (item.getRiskAcceptedById() != null) {
                userIds.add(item.getRiskAcceptedById());
            }
            if (item.getRiskApprovedById() != null) {
                userIds.add(item.getRiskApprovedById());
            }
        }
        Map<UUID, String> names = userNames(userIds);

        LocalDateTime now = LocalDateTime.now();
        List<ActionItemResponse> result = new ArrayList<>(items.size());
        for (ActionItem item : items) {
            List<ActionItemFinding> links = linksByItem.getOrDefault(item.getId(), List.of());
            List<ResolvedFinding> linked = links.stream().map(l -> resolved.get(l.ref())).filter(Objects::nonNull).toList();
            RemediationStatusDeriver.ActionItemSnapshot snapshot = new RemediationStatusDeriver.ActionItemSnapshot(
                    item.getStatus(), item.getResolvedAt(), item.getRiskAcceptedUntil());
            RemediationStatusDeriver.ItemStatus itemStatus = RemediationStatusDeriver.forItem(snapshot, linked, now);

            result.add(new ActionItemResponse(
                    item.getId(), item.getTitle(),
                    item.getProductId(), item.getProductId() == null ? null : productNames.get(item.getProductId()),
                    item.getAssetId(), item.getAssetId() == null ? null : assetNames.get(item.getAssetId()),
                    itemStatus.status(), item.getStatus(), itemStatus.derivation(),
                    itemStatus.reopened(), itemStatus.reopenedFindings(),
                    itemStatus.riskAcceptanceExpired(), itemStatus.awaitingVerification(), itemStatus.fixVerified(),
                    item.getAssigneeId(), item.getAssigneeId() == null ? null : names.get(item.getAssigneeId()),
                    linked.size(), remainingCount(linked), countsByType(links),
                    score(linked),
                    item.getStatus() == RemediationStatus.RISK_ACCEPTED ? riskAcceptance(item, names) : null,
                    item.getCreatedAt(), item.getCreatedById(), item.getUpdatedAt(), item.getResolvedAt()));
        }
        return result;
    }

    private static long remainingCount(List<ResolvedFinding> linked) {
        return linked.stream()
                .filter(f -> f.lifecycleState() == AlertLifecycleState.ACTIVE)
                .filter(f -> !(f.type() == FindingType.VULNERABILITY
                        && (f.vexStatus() == VexStatus.NOT_AFFECTED || f.vexStatus() == VexStatus.FIXED)))
                .count();
    }

    private static Map<FindingType, Long> countsByType(List<ActionItemFinding> links) {
        Map<FindingType, Long> counts = new LinkedHashMap<>();
        for (ActionItemFinding link : links) {
            counts.merge(link.getFindingType(), 1L, Long::sum);
        }
        return counts;
    }

    private static ActionItemScore score(List<ResolvedFinding> linked) {
        List<ResolvedFinding> remainingVulns = linked.stream()
                .filter(f -> f.type() == FindingType.VULNERABILITY)
                .filter(f -> f.lifecycleState() == AlertLifecycleState.ACTIVE)
                .filter(f -> f.vexStatus() != VexStatus.NOT_AFFECTED && f.vexStatus() != VexStatus.FIXED)
                .toList();
        long scored = remainingVulns.stream().filter(f -> f.riskScore() != null).count();
        long unscored = remainingVulns.size() - scored;
        Double max = null;
        UUID topId = null;
        for (ResolvedFinding f : remainingVulns) {
            if (f.riskScore() != null && (max == null || f.riskScore() > max)) {
                max = f.riskScore();
                topId = f.id();
            }
        }
        return new ActionItemScore(max, topId, scored, unscored);
    }

    private RiskAcceptance riskAcceptance(ActionItem item, Map<UUID, String> names) {
        return new RiskAcceptance(
                item.getRiskAcceptedUntil(), item.getRiskAcceptedAt(), item.getRiskAcceptedById(),
                item.getRiskAcceptedById() == null ? null : names.get(item.getRiskAcceptedById()),
                item.getRiskAcceptanceJustification(), item.getRiskApprovedById(),
                item.getRiskApprovedById() == null ? null : names.get(item.getRiskApprovedById()),
                item.getRiskApprovalNote());
    }

    private Map<UUID, String> userNames(Set<UUID> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return appUserRepository.findAllById(ids).stream()
                .collect(Collectors.toMap(User::getId, ActionItemService::displayName));
    }

    private static String displayName(User user) {
        return user.getDisplayName() != null ? user.getDisplayName() : user.getEmail();
    }

    /* ------------------------------------------------------------------ */
    /* Events                                                              */
    /* ------------------------------------------------------------------ */

    private ActionItemEvent appendEvent(ActionItem item, ActionItemEventType type, RemediationStatus from,
                                         RemediationStatus to, StatusDerivation derivation, FindingType findingType,
                                         UUID findingId, UUID assigneeId, LocalDateTime riskAcceptedUntil, User actingUser) {
        return appendEvent(item, type, from, to, derivation, findingType, findingId, assigneeId, riskAcceptedUntil,
                actingUser, null);
    }

    private ActionItemEvent appendEvent(ActionItem item, ActionItemEventType type, RemediationStatus from,
                                         RemediationStatus to, StatusDerivation derivation, FindingType findingType,
                                         UUID findingId, UUID assigneeId, LocalDateTime riskAcceptedUntil, User actingUser,
                                         String comment) {
        ActionItemEvent event = new ActionItemEvent();
        event.setTenantId(item.getTenantId());
        event.setActionItemId(item.getId());
        event.setEventType(type);
        event.setFromStatus(from);
        event.setToStatus(to);
        event.setDerivation(derivation);
        event.setFindingType(findingType);
        event.setFindingId(findingId);
        event.setAssigneeId(assigneeId);
        event.setRiskAcceptedUntil(riskAcceptedUntil);
        event.setComment(comment);
        event.setChangedById(actingUser == null ? item.getCreatedById() : actingUser.getId());
        return actionItemEventRepository.save(event);
    }

    private static ActionItemEventResponse toEventResponse(ActionItemEvent event, Map<UUID, String> names) {
        return new ActionItemEventResponse(
                event.getId(), event.getEventType(), event.getFromStatus(), event.getToStatus(), event.getDerivation(),
                event.getFindingType(), event.getFindingId(), event.getAssigneeId(), event.getRiskAcceptedUntil(),
                event.getRiskApprovedById(), event.getComment(), event.getChangedById(),
                names.get(event.getChangedById()), event.getCreatedAt());
    }

}
