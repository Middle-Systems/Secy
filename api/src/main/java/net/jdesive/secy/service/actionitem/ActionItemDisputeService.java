package net.jdesive.secy.service.actionitem;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionitem.DisputeFindingRequest;
import net.jdesive.secy.model.actionitem.DisputeResponse;
import net.jdesive.secy.model.vex.AuthorVexStatementRequest;
import net.jdesive.secy.persistence.ActionItemFindingRepository;
import net.jdesive.secy.persistence.entity.ActionItem;
import net.jdesive.secy.persistence.entity.ActionItemFinding;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.service.vex.AuthoredVex;
import net.jdesive.secy.service.vex.VexAuthoringService;
import net.jdesive.secy.service.vex.parser.VexParsing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * "Dispute with a VEX justification" (M1k — ROADMAP.md's "Role-based views" §7). <b>A dispute IS a
 * TENANT-origin OpenVEX {@code not_affected} statement authored on the user's behalf — no separate
 * dispute mechanism.</b> This class only does the item/finding/scope validation specific to
 * disputing; the actual authoring and ingestion run through {@link VexAuthoringService} unchanged.
 *
 * <p>Takes effect immediately, no approval step — matches M1j's schema-only risk acceptance and
 * M1f's "tenant overrides vendor" default. There is deliberately no ownership/role check on who may
 * dispute (Tenancy hardening's job). Only vulnerability findings with a CVE id, a resolvable PURL and
 * a product scope can be disputed — a compromise/drift/quantum/quality finding has no VEX concept
 * (use {@code RISK_ACCEPTED}, M1j), and an asset-derived alert has no product to scope the statement
 * to (an unscoped statement would apply tenant-wide, which is not what "dispute this one finding"
 * means).
 */
@Service
@RequiredArgsConstructor
public class ActionItemDisputeService {

    private static final int MAX_IMPACT_STATEMENT_LENGTH = 4096;

    private final ActionItemService actionItemService;
    private final ActionItemFindingRepository actionItemFindingRepository;
    private final VulnerabilityAlertRepository alertRepository;
    private final VexAuthoringService vexAuthoringService;

    @Transactional
    public DisputeResponse dispute(UUID itemId, DisputeFindingRequest request, User actingUser, Principal principal) {
        if (request == null || request.findingId() == null) {
            throw new InvalidActionItemException("findingId is required");
        }
        if (request.impactStatement() == null || request.impactStatement().isBlank()) {
            throw new InvalidActionItemException("impactStatement is required and must not be blank");
        }
        if (request.impactStatement().length() > MAX_IMPACT_STATEMENT_LENGTH) {
            throw new InvalidActionItemException("impactStatement is " + request.impactStatement().length()
                    + " characters, over the " + MAX_IMPACT_STATEMENT_LENGTH + " limit");
        }

        ActionItem item = actionItemService.requireItem(itemId);

        ActionItemFinding link = findLinkAnyType(request.findingId())
                .orElseThrow(() -> new InvalidActionItemException(
                        "finding " + request.findingId() + " is not attached to any action item"));

        if (link.getFindingType() != FindingType.VULNERABILITY) {
            throw new InvalidActionItemException(
                    "compromise/drift/quantum/quality findings have no VEX concept — use RISK_ACCEPTED (M1j)");
        }
        if (!Objects.equals(link.getActionItemId(), item.getId())) {
            throw new InvalidActionItemException(
                    "finding " + request.findingId() + " is not attached to this action item");
        }

        VulnerabilityAlert alert = alertRepository.findById(request.findingId())
                .orElseThrow(() -> new InvalidActionItemException("finding " + request.findingId() + " no longer exists"));

        SBOMComponent component = alert.getComponent();
        if (component == null || component.getSbom() == null || component.getSbom().getProduct() == null) {
            throw new InvalidActionItemException(
                    "VEX has no asset scope; an unscoped statement would apply tenant-wide");
        }

        VexParsing.PurlTarget purlTarget = VexParsing.purlTarget(component.getPurl());
        if (purlTarget.matchKey() == null || !purlTarget.matchKey().equals(component.getIdentityKey())) {
            throw new InvalidActionItemException("dispute could never apply -- this component has no resolvable PURL");
        }

        String cveId = alert.getVulnerability() == null ? null : alert.getVulnerability().getId();
        if (cveId == null) {
            throw new InvalidActionItemException("finding " + request.findingId() + " has no CVE id");
        }

        UUID productId = component.getSbom().getProduct().getId();

        AuthorVexStatementRequest authorRequest = new AuthorVexStatementRequest(
                cveId, productId, component.getPurl(), VexStatus.NOT_AFFECTED,
                request.justification(), request.impactStatement(), null);

        AuthoredVex authored = vexAuthoringService.author(authorRequest, actingUser.getEmail(), principal);

        var event = actionItemService.recordDispute(item, request.findingId(), authored.documentId(),
                request.impactStatement(), actingUser);

        return new DisputeResponse(authored.job(), authored.documentId(), event);
    }

    private Optional<ActionItemFinding> findLinkAnyType(UUID findingId) {
        Optional<ActionItemFinding> link = actionItemFindingRepository.findByVulnerabilityAlertId(findingId);
        if (link.isPresent()) {
            return link;
        }
        link = actionItemFindingRepository.findByCompromiseFindingId(findingId);
        if (link.isPresent()) {
            return link;
        }
        link = actionItemFindingRepository.findByLifecycleDriftFindingId(findingId);
        if (link.isPresent()) {
            return link;
        }
        link = actionItemFindingRepository.findByQuantumVulnerabilityFindingId(findingId);
        if (link.isPresent()) {
            return link;
        }
        return actionItemFindingRepository.findBySbomQualityFindingId(findingId);
    }

}
