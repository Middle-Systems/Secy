package net.jdesive.secy.service.access;

import net.jdesive.secy.model.access.RoleSource;
import net.jdesive.secy.model.access.TenantAdminSource;
import net.jdesive.secy.model.access.UpdateTenantMemberRequest;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.TenantRepository;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TenantMembership;
import net.jdesive.secy.persistence.entity.TenantRole;
import net.jdesive.secy.persistence.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** M1k's T2 — see ROADMAP.md's M1k section 10. */
@SpringBootTest
@Transactional
class TenantAccessServiceTest {

    @Autowired
    private TenantAccessService tenantAccessService;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository membershipRepository;

    private User newUser(Role role) {
        User user = new User();
        user.setEmail("t2-" + UUID.randomUUID() + "@example.com");
        user.setPasswordHash("{noop}unused");
        user.setDisplayName("T2 Tester");
        user.setRole(role);
        user.setEnabled(true);
        return userRepository.save(user);
    }

    private TenantMembership newMembership(User user) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenantRepository.getReferenceById(Tenant.DEFAULT_TENANT_ID));
        membership.setUser(user);
        return membershipRepository.save(membership);
    }

    @Test
    void unconfiguredMembershipDefaultsToSecurityEngineer() {
        User user = newUser(Role.USER);
        newMembership(user);

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, user.getId());

        assertThat(access.member()).isTrue();
        assertThat(access.roles()).containsExactly(TenantRole.SECURITY_ENGINEER);
        assertThat(access.rolesSource()).isEqualTo(RoleSource.DEFAULT);
        assertThat(access.defaultView()).isEqualTo(TenantRole.SECURITY_ENGINEER);
    }

    @Test
    void explicitRolesReportInEnumOrderWithSoftwareEngineerDefaultView() {
        User admin = newUser(Role.ADMIN);
        newMembership(admin);
        User user = newUser(Role.USER);
        newMembership(user);

        tenantAccessService.updateMember(Tenant.DEFAULT_TENANT_ID, user.getId(),
                new UpdateTenantMemberRequest(List.of(TenantRole.SOFTWARE_ENGINEER, TenantRole.LEADERSHIP), null, null),
                admin.getId());

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, user.getId());

        assertThat(access.rolesSource()).isEqualTo(RoleSource.EXPLICIT);
        assertThat(access.views()).containsExactly(TenantRole.LEADERSHIP, TenantRole.SOFTWARE_ENGINEER);
        assertThat(access.defaultView()).isEqualTo(TenantRole.SOFTWARE_ENGINEER);
    }

    @Test
    void explicitEmptyRolesMeansNoViewsAndNullDefaultView() {
        User admin = newUser(Role.ADMIN);
        newMembership(admin);
        User user = newUser(Role.USER);
        newMembership(user);

        tenantAccessService.updateMember(Tenant.DEFAULT_TENANT_ID, user.getId(),
                new UpdateTenantMemberRequest(List.of(), null, null), admin.getId());

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, user.getId());

        assertThat(access.rolesSource()).isEqualTo(RoleSource.EXPLICIT);
        assertThat(access.views()).isEmpty();
        assertThat(access.defaultView()).isNull();
    }

    @Test
    void globalAdminIsAlwaysEffectiveTenantAdminRegardlessOfMembershipFlag() {
        User admin = newUser(Role.ADMIN);
        TenantMembership membership = newMembership(admin);
        // Even explicitly revoked on the membership row, the global admin override still wins.
        membership.setTenantAdmin(false);
        membershipRepository.save(membership);

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, admin.getId());

        assertThat(access.tenantAdmin()).isTrue();
        assertThat(access.tenantAdminSource()).isEqualTo(TenantAdminSource.GLOBAL_ADMIN);
    }

    @Test
    void membershipFlagGrantsTenantAdminForANonGlobalAdmin() {
        User user = newUser(Role.USER);
        TenantMembership membership = newMembership(user);
        membership.setTenantAdmin(true);
        membershipRepository.save(membership);

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, user.getId());

        assertThat(access.tenantAdmin()).isTrue();
        assertThat(access.tenantAdminSource()).isEqualTo(TenantAdminSource.MEMBERSHIP);
    }

    @Test
    void nonMemberHasNoViewsAndIsNotAMember() {
        User user = newUser(Role.USER);
        // No membership row created for this user.

        TenantAccess access = tenantAccessService.accessFor(Tenant.DEFAULT_TENANT_ID, user.getId());

        assertThat(access.member()).isFalse();
        assertThat(access.views()).isEmpty();
        assertThat(access.tenantAdmin()).isFalse();
    }

    @Test
    void requireTenantAdminThrows403ForANonAdmin() {
        User user = newUser(Role.USER);
        newMembership(user);

        assertThatThrownBy(() -> tenantAccessService.requireTenantAdmin(Tenant.DEFAULT_TENANT_ID, user.getId()))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("403");
    }

}
