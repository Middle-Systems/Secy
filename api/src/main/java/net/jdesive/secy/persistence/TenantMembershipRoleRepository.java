package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.TenantMembershipRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** {@code exported = false} — see {@code TenantRepository}'s Javadoc for why. */
@RepositoryRestResource(exported = false)
public interface TenantMembershipRoleRepository extends JpaRepository<TenantMembershipRole, UUID> {

    List<TenantMembershipRole> findByMembershipId(UUID membershipId);

    List<TenantMembershipRole> findByMembershipIdIn(Collection<UUID> membershipIds);

    void deleteByMembershipId(UUID membershipId);

}
