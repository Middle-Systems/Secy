package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;

import java.util.UUID;

/**
 * The {@code GET /actionable} query string, parsed. Every field is optional; a null means
 * "no restriction on this dimension".
 *
 * @param productId          only alerts on SBOMs belonging to this product
 * @param assetId            <b>accepted and ignored.</b> There is no {@code Asset} entity until
 *                           Phase 4, so nothing can match it; the parameter exists now so the UI's
 *                           filter contract does not change when assets land. Filtering to nothing
 *                           was the alternative and would have read as a bug.
 * @param reason             exact {@link ActionableReason}. Note {@code KEV_AND_EPSS_HIGH} is its
 *                           own value — filtering on {@code KEV} does not include it.
 * @param minCvss            CVSS base score at or above this. Alerts whose CVE has no score are
 *                           excluded, since "unscored" is not "below the bar".
 * @param state              <b>accepted and ignored.</b> Reserved for the Phase 7 triage state
 *                           machine (OPEN / ACKNOWLEDGED / SNOOZED / RESOLVED / FALSE_POSITIVE);
 *                           there is no state column yet.
 * @param fixState           exact {@link FixState}
 * @param minExploitMaturity {@link ExploitMaturity} at or above this, by the enum's declaration
 *                           order. {@code NONE} is a no-op since everything is at least NONE.
 * @param matchConfidence    exact {@link MatchConfidence}, mirroring {@code fixState}. Filtering to
 *                           {@code EXACT} is how an operator asks for "only what I am certain
 *                           about"; there is deliberately no "at or above" form, because the useful
 *                           question in practice is the exact band.
 */
public record ActionableFilter(
        UUID productId,
        UUID assetId,
        ActionableReason reason,
        Double minCvss,
        String state,
        FixState fixState,
        ExploitMaturity minExploitMaturity,
        MatchConfidence matchConfidence) {
}
