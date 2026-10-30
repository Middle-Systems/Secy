package net.jdesive.secy.model.finding;

import jakarta.validation.constraints.NotNull;
import net.jdesive.secy.persistence.entity.FindingType;

import java.util.UUID;

/**
 * A typed reference to one row of the M1j {@code Finding} union — the request-element shape for
 * every endpoint that names a finding ({@code POST /action-items}, {@code .../findings}) and the
 * response shape wherever one needs to be named back (a reopened finding, a detached one).
 *
 * @param type the finding's table, per {@link net.jdesive.secy.persistence.entity.FindingType}
 * @param id   its row id in that table
 */
public record FindingRef(
        @NotNull FindingType type,
        @NotNull UUID id) {
}
