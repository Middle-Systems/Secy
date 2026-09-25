package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatement;

import java.util.List;

/**
 * {@code VexResolutionService.explain}'s return type — every statement applicable to one alert, with
 * the role {@link VexResolver#resolve} gave it, plus the policy that produced the resolution.
 * Server-internal: {@code ActionableService} maps this onto
 * {@code ActionableDetailResponse.Vex}/{@code AppliedVexStatement} for the actual API response.
 */
public record VexExplanation(VexPrecedencePolicy policy, List<Applied> statements) {

    public record Applied(VexStatement statement, VexStatementRole role) {
    }

}
