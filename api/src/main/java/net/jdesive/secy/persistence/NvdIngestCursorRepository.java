package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.NvdIngestCursor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * NVD's high-water mark — one fixed row, id {@code "nvd"}. Written by {@code NVDService} after each
 * completed incremental window; not read by the correlation path. See {@link NvdIngestCursor}.
 */
@Repository
public interface NvdIngestCursorRepository extends JpaRepository<NvdIngestCursor, String> {
}
