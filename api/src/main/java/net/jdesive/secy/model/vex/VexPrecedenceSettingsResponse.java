package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;

/**
 * {@code GET}/{@code PUT /vex/settings/precedence}. {@code alertsEvaluated}/{@code alertsChanged} are
 * null on a {@code GET} (nothing was reconciled) and populated on a {@code PUT}, which re-resolves
 * everything the change could affect before returning.
 */
public record VexPrecedenceSettingsResponse(VexPrecedencePolicy policy, Integer alertsEvaluated, Integer alertsChanged) {

    public static VexPrecedenceSettingsResponse of(VexPrecedencePolicy policy) {
        return new VexPrecedenceSettingsResponse(policy, null, null);
    }

}
