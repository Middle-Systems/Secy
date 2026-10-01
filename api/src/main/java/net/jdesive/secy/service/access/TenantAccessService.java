package net.jdesive.secy.service.access;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.access.RoleSource;
import net.jdesive.secy.model.access.TenantAdminSource;
import net.jdesive.secy.model.access.TenantMemberResponse;
import net.jdesive.secy.model.access.UpdateTenantMemberRequest;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.TenantMembershipRoleRepository;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.TenantMembership;
import net.jdesive.secy.persistence.entity.TenantMembershipRole;
import net.jdesive.secy.persistence.entity.TenantRole;
import net.jdesive.secy.persistence.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Role/membership access logic for M1k (ROADMAP.md — "Role-based views"). <b>No enforcement.</b>
 * Every computation here answers "which views should the UI show" or, for
 * {@link #requireTenantAdmin}, the one deliberate exception the plan carves out: the brand-new
 * role-assignment write endpoint is gated to tenant admins because that gate is intrinsic to the
 * feature itself, not a retrofit onto an existing one. Nothing else in this codebase calls
 * {@link #requireTenantAdmin} yet — see the {@code TODO(tenancy-hardening)} comments on
 * {@code ProductOwnershipController}, {@code RiskScoreController} and {@code LineageController}
 * naming this method as the seam a later milestone will wire up.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class TenantAccessService {

    /** What an unconfigured membership ({@code rolesConfigured=false}) resolves to — today's
     *  Actionable Items experience, unchanged for every existing/new user. */
    public static final Set<TenantRole> DEFAULT_ROLES = EnumSet.of(TenantRole.SECURITY_ENGINEER);

    /** {@code defaultView} priority — first of these present in the effective role set wins. */
    private static final List<TenantRole> DEFAULT_VIEW_PRIORITY =
            List.of(TenantRole.SECURITY_ENGINEER, TenantRole.SOFTWARE_ENGINEER, TenantRole.LEADERSHIP);

    private final AppUserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final TenantMembershipRoleRepository membershipRoleRepository;

    /* ------------------------------------------------------------------ */
    /* Read                                                                */
    /* ------------------------------------------------------------------ */

    @Transactional(readOnly = true)
    public TenantAccess accessFor(UUID tenantId, UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found: " + userId));
        TenantMembership membership = membershipRepository.findByTenantIdAndUserId(tenantId, userId).orElse(null);
        return buildAccess(tenantId, user, membership);
    }

    /** Throws 403 unless {@code userId} is an effective tenant admin of {@code tenantId}. */
    @Transactional(readOnly = true)
    public void requireTenantAdmin(UUID tenantId, UUID userId) {
        if (!accessFor(tenantId, userId).tenantAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "tenant admin required");
        }
    }

    @Transactional(readOnly = true)
    public List<TenantMemberResponse> listMembers(UUID tenantId) {
        return membershipRepository.findAllByTenantId(tenantId).stream()
                .map(m -> toMemberResponse(tenantId, m.getUser(), m))
                .sorted(Comparator.comparing(TenantMemberResponse::email))
                .toList();
    }

    /* ------------------------------------------------------------------ */
    /* Write                                                               */
    /* ------------------------------------------------------------------ */

    public TenantMemberResponse updateMember(UUID tenantId, UUID targetUserId, UpdateTenantMemberRequest request,
                                              UUID actingUserId) {
        if (request == null) {
            throw new InvalidTenantAccessException("request body is required");
        }
        boolean rolesSet = request.roles() != null;
        boolean resetSet = Boolean.TRUE.equals(request.resetRolesToDefault());
        boolean adminSet = request.tenantAdmin() != null;

        if (rolesSet && resetSet) {
            throw new InvalidTenantAccessException("roles and resetRolesToDefault can't both be set");
        }
        if (!rolesSet && !resetSet && !adminSet) {
            throw new InvalidTenantAccessException("nothing to update — set roles, resetRolesToDefault, or tenantAdmin");
        }
        if (rolesSet && request.roles().stream().anyMatch(java.util.Objects::isNull)) {
            throw new InvalidTenantAccessException("roles must not contain a null element");
        }

        TenantMembership membership = membershipRepository.findByTenantIdAndUserId(tenantId, targetUserId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "user " + targetUserId + " is not a member of this tenant"));

        if (resetSet) {
            membershipRoleRepository.deleteByMembershipId(membership.getId());
            membership.setRolesConfigured(false);
        } else if (rolesSet) {
            membershipRoleRepository.deleteByMembershipId(membership.getId());
            Set<TenantRole> distinct = new HashSet<>(request.roles());
            for (TenantRole role : distinct) {
                TenantMembershipRole row = new TenantMembershipRole();
                row.setMembershipId(membership.getId());
                row.setRole(role);
                membershipRoleRepository.save(row);
            }
            membership.setRolesConfigured(true);
        }

        if (adminSet) {
            membership.setTenantAdmin(request.tenantAdmin());
        }

        membership.setAccessUpdatedAt(LocalDateTime.now());
        membership.setAccessUpdatedById(actingUserId);
        membership = membershipRepository.save(membership);

        log.info("Tenant access for user {} in tenant {} updated by {} (roles={}, resetToDefault={}, tenantAdmin={})",
                targetUserId, tenantId, actingUserId, request.roles(), request.resetRolesToDefault(), request.tenantAdmin());

        return toMemberResponse(tenantId, membership.getUser(), membership);
    }

    /* ------------------------------------------------------------------ */
    /* Shared computation                                                  */
    /* ------------------------------------------------------------------ */

    private TenantAccess buildAccess(UUID tenantId, User user, TenantMembership membership) {
        boolean member = membership != null;
        boolean globalAdmin = user.getRole() == Role.ADMIN;
        boolean storedAdmin = member && membership.isTenantAdmin();
        boolean effectiveAdmin = globalAdmin || storedAdmin;
        // Both could apply; GLOBAL_ADMIN is reported per the plan's D3.
        TenantAdminSource adminSource = !effectiveAdmin ? null
                : (globalAdmin ? TenantAdminSource.GLOBAL_ADMIN : TenantAdminSource.MEMBERSHIP);

        Set<TenantRole> roles;
        RoleSource rolesSource;
        if (!member) {
            roles = EnumSet.noneOf(TenantRole.class);
            rolesSource = RoleSource.DEFAULT;
        } else if (membership.isRolesConfigured()) {
            roles = membershipRoleRepository.findByMembershipId(membership.getId()).stream()
                    .map(TenantMembershipRole::getRole)
                    .collect(() -> EnumSet.noneOf(TenantRole.class), Set::add, Set::addAll);
            rolesSource = RoleSource.EXPLICIT;
        } else {
            roles = EnumSet.copyOf(DEFAULT_ROLES);
            rolesSource = RoleSource.DEFAULT;
        }

        List<TenantRole> views = roles.stream().sorted().toList();
        TenantRole defaultView = DEFAULT_VIEW_PRIORITY.stream().filter(roles::contains).findFirst().orElse(null);

        return new TenantAccess(tenantId, member, effectiveAdmin, adminSource, roles, rolesSource, views, defaultView);
    }

    private TenantMemberResponse toMemberResponse(UUID tenantId, User user, TenantMembership membership) {
        TenantAccess access = buildAccess(tenantId, user, membership);
        return new TenantMemberResponse(
                user.getId(), user.getEmail(), user.getDisplayName(), user.isEnabled(), user.getRole(),
                access.tenantAdmin(), access.tenantAdminSource(), membership.isTenantAdmin(),
                access.views(), access.rolesSource(),
                membership.getAccessUpdatedAt(), membership.getAccessUpdatedById());
    }

}
