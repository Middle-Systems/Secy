package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.OsvEcosystemCursor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * High-water marks for the OSV mirror, one row per ecosystem, keyed by the ecosystem name.
 *
 * <p>Written by the OSV feed ingester after a successful per-ecosystem pull; not read by the
 * correlation path. See {@link OsvEcosystemCursor}.
 */
@Repository
public interface OsvEcosystemCursorRepository extends JpaRepository<OsvEcosystemCursor, String> {
}
