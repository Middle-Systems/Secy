package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TenantMembership;
import net.jdesive.secy.persistence.entity.TenantMembershipRole;
import net.jdesive.secy.persistence.entity.TenantRole;
import net.jdesive.secy.persistence.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1k's T1 — the <b>mandatory gate</b> the plan requires passing before anything else is built on
 * top of the role-assignment schema (see ROADMAP.md's M1k section 2). The plan's original design
 * called for {@code @ElementCollection Set<TenantRole> roles} directly on {@code TenantMembership}
 * with {@code @OnDelete(CASCADE)} — Hibernate 6.5.3 rejects that combination outright (see
 * {@code TenantMembership}'s class Javadoc), so this proves the plan's own pre-decided fallback
 * instead: a satellite {@link TenantMembershipRole} entity with a plain, un-related
 * {@code membershipId} column.
 *
 * <p>Deliberately NOT {@code @Transactional}: several existing non-transactional test classes
 * ({@code TenancyFoundationTest}, {@code AuthIntegrationTest}, {@code OwnershipServiceTest}) call
 * {@code userRepository.deleteAll()} between tests against the shared H2 database and rely on that
 * succeeding via {@code TenantMembership.user}'s {@code @OnDelete(CASCADE)} — this proves a role row
 * never blocks that, because {@link TenantMembershipRole} carries no JPA relation back to
 * {@code TenantMembership} at all (so Hibernate generates no H2 foreign key between the two tables).
 */
@SpringBootTest
class TenantMembershipRoleCascadeTest {

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private TenantMembershipRoleRepository tenantMembershipRoleRepository;

    @BeforeEach
    void cleanUp() {
        userRepository.deleteAll();
    }

    @Test
    void rolesRoundTripAndUserDeleteCascadesTheRoleTable() {
        User user = new User();
        user.setEmail("t1-cascade-tester@example.com");
        user.setPasswordHash("{noop}unused");
        user.setDisplayName("T1 Cascade Tester");
        user.setRole(Role.USER);
        user.setEnabled(true);
        user = userRepository.save(user);

        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenantRepository.getReferenceById(Tenant.DEFAULT_TENANT_ID));
        membership.setUser(user);
        membership.setRolesConfigured(true);
        membership = tenantMembershipRepository.save(membership);

        TenantMembershipRole r1 = new TenantMembershipRole();
        r1.setMembershipId(membership.getId());
        r1.setRole(TenantRole.SOFTWARE_ENGINEER);
        tenantMembershipRoleRepository.save(r1);

        TenantMembershipRole r2 = new TenantMembershipRole();
        r2.setMembershipId(membership.getId());
        r2.setRole(TenantRole.LEADERSHIP);
        tenantMembershipRoleRepository.save(r2);

        List<TenantMembershipRole> reloaded = tenantMembershipRoleRepository.findByMembershipId(membership.getId());
        assertThat(reloaded).extracting(TenantMembershipRole::getRole)
                .containsExactlyInAnyOrder(TenantRole.SOFTWARE_ENGINEER, TenantRole.LEADERSHIP);

        // The mandatory gate: deleting the user must succeed (cascading tenant_membership at the DB
        // level), and must not be blocked by the orphaned tenant_membership_role rows left behind —
        // there is no FK from that table to tenant_membership under H2's entity-derived schema.
        userRepository.deleteAll();

        assertThat(tenantMembershipRepository.findByUserId(user.getId())).isEmpty();
    }

}
