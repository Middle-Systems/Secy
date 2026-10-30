package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.SBOMComponentIdentityConflict;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * M1c (ROADMAP.md — "Canonical component identity"). Conflict rows are read through
 * {@code ComponentIdentityService#describe} via the owning {@link net.jdesive.secy.persistence.entity.SBOMComponent}'s
 * collection; this repository exists for symmetry with {@link SBOMComponentRepository} and any
 * future direct lookup, not because anything queries it standalone yet. Not exported over Spring
 * Data REST, same as every other repository here — these rows are evidence, not something a
 * client should be able to fabricate or delete directly.
 */
@Repository
@RepositoryRestResource(exported = false)
public interface SBOMComponentIdentityConflictRepository extends JpaRepository<SBOMComponentIdentityConflict, UUID> {
}
