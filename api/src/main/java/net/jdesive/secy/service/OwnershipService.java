package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.ownership.ProductOwnerRequest;
import net.jdesive.secy.model.ownership.ProductOwnerResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.OwnershipLinkRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.entity.OwnerType;
import net.jdesive.secy.persistence.entity.OwnershipLink;
import net.jdesive.secy.persistence.entity.OwnershipSource;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

/**
 * M1b's manual ownership assignment (see ROADMAP.md's "M1b — Ownership model").
 *
 * <p>H2's test schema is built from the entities ({@code ddl-auto=create-drop}), not Liquibase, so
 * the Postgres-only CHECK constraints and partial unique indexes from migration {@code 020} have no
 * effect under test — every rule they encode is re-checked here too, not just relied on at the DB
 * level.
 */
@Service
@RequiredArgsConstructor
public class OwnershipService {

    private final OwnershipLinkRepository ownershipLinkRepository;
    private final ProductRepository productRepository;
    private final AppUserRepository appUserRepository;
    private final TenantMembershipRepository tenantMembershipRepository;

    @Transactional(readOnly = true)
    public List<ProductOwnerResponse> listProductOwners(UUID productId) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Product not found"));

        return ownershipLinkRepository.findByProductIdOrderByCreatedAtAsc(product.getId()).stream()
                .map(ProductOwnerResponse::from)
                .toList();
    }

    @Transactional
    public ProductOwnerResponse assignManualProductOwner(UUID productId, ProductOwnerRequest req, User actingUser) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Product not found"));

        if (product.isUnassigned()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "The Unassigned product can't have owners — move its SBOMs to a real product first");
        }

        if (req == null || req.ownerType() == null) {
            throw new InvalidOwnershipException("ownerType is required and must be USER or TEAM");
        }

        OwnershipLink link = new OwnershipLink();
        link.setOwnerType(req.ownerType());

        switch (req.ownerType()) {
            case USER -> assignUserOwner(product, req, link);
            case TEAM -> assignTeamOwner(product, req, link);
        }

        link.setProduct(product);
        link.setTenantId(product.getTenantId());
        link.setSource(OwnershipSource.MANUAL);
        link.setInferenceMethod(null);
        link.setEvidence(null);
        link.setAssignedBy(actingUser);

        return ProductOwnerResponse.from(ownershipLinkRepository.save(link));
    }

    private void assignUserOwner(Product product, ProductOwnerRequest req, OwnershipLink link) {
        if (req.userId() == null) {
            throw new InvalidOwnershipException("userId is required for a USER owner");
        }
        if (req.principal() != null && !req.principal().isBlank()) {
            throw new InvalidOwnershipException("a manual USER owner can't also carry a free-text principal");
        }

        User user = appUserRepository.findById(req.userId())
                .orElseThrow(() -> new InvalidOwnershipException("no user found with id " + req.userId()));

        if (!user.isEnabled()) {
            throw new InvalidOwnershipException("user " + user.getEmail() + " is disabled");
        }

        if (!tenantMembershipRepository.existsByTenantIdAndUserId(product.getTenantId(), user.getId())) {
            throw new InvalidOwnershipException(
                    "user " + user.getEmail() + " is not a member of this product's tenant");
        }

        if (ownershipLinkRepository.existsByProductIdAndOwnerTypeAndUserIdAndSource(
                product.getId(), OwnerType.USER, user.getId(), OwnershipSource.MANUAL)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "user " + user.getEmail() + " already manually owns this product");
        }

        link.setUser(user);
        link.setPrincipal(null);
    }

    private void assignTeamOwner(Product product, ProductOwnerRequest req, OwnershipLink link) {
        if (req.userId() != null) {
            throw new InvalidOwnershipException("a TEAM owner can't carry a userId");
        }

        String principal = req.principal() == null ? null : req.principal().trim();
        if (principal == null || principal.isEmpty()) {
            throw new InvalidOwnershipException("principal is required for a TEAM owner");
        }
        if (principal.length() > 255) {
            throw new InvalidOwnershipException("principal is " + principal.length()
                    + " characters, over the 255 limit");
        }
        if (principal.chars().anyMatch(Character::isISOControl)) {
            throw new InvalidOwnershipException("principal must not contain control characters");
        }

        if (ownershipLinkRepository.existsByProductIdAndOwnerTypeAndPrincipalIgnoreCaseAndSource(
                product.getId(), OwnerType.TEAM, principal, OwnershipSource.MANUAL)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "team '" + principal + "' already manually owns this product");
        }

        link.setUser(null);
        link.setPrincipal(principal);
    }

    @Transactional
    public void removeManualProductOwner(UUID productId, UUID linkId) {
        OwnershipLink link = ownershipLinkRepository.findByIdAndProductId(linkId, productId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership link not found"));

        if (link.getSource() == OwnershipSource.INFERRED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "inferred ownership is managed by its connector; add a MANUAL link to override");
        }

        ownershipLinkRepository.delete(link);
    }

    /**
     * The products a user owns within a tenant — M1k's seam for the software-engineer "my products"
     * filter. No caller yet in M1b.
     */
    @Transactional(readOnly = true)
    public List<UUID> productIdsOwnedBy(UUID tenantId, UUID userId) {
        return ownershipLinkRepository.findOwnedProductIds(tenantId, userId);
    }
}
