package net.jdesive.secy.model.finding;

import net.jdesive.secy.persistence.entity.FindingType;

/**
 * One row of {@code GET /findings/types} — the finding-type inventory, honest about what's stubbed.
 *
 * @param type      the discriminator value
 * @param available {@link FindingType#backedByTable()} — false only for {@code PROVENANCE}
 * @param note      an explanatory note, populated only when {@code available} is false
 */
public record FindingTypeInfo(FindingType type, boolean available, String note) {
}
