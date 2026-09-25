package net.jdesive.secy.lineage.source;

import java.time.LocalDateTime;
import java.util.UUID;

/** One {@code Product} row, as read for lineage planning (JPQL constructor projection). */
public record ProductRow(UUID id, String name, String tagValue, boolean unassigned, LocalDateTime createdAt) {
}
