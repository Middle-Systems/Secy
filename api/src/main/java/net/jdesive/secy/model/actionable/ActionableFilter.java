package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;

import java.util.UUID;

/**
 * The {@code GET /actionable} query string, parsed. Every field is optional; a null means
 * "no restriction on this dimension".
 *
 * <h2>How a filter applies across the two arms of the union</h2>
 *
 * <p>Since Phase 6 this endpoint returns two kinds of row, and a filter has to say what it means for
 * each. The rule is: <b>a filter that only one arm can satisfy excludes the other arm entirely.</b>
 * Asking for {@code minCvss=7} is asking about CVSS, and a compromise finding has no CVSS score —
 * returning it anyway because "it is critical, so surely they want it" would make the filter a lie.
 * The one thing that is never silently dropped is scope: {@code productId} and {@code assetId} apply
 * to both arms identically.
 *
 * <table border="1">
 *   <caption>Effect of each filter on each arm</caption>
 *   <tr><th>Filter</th><th>Vulnerability rows</th><th>Compromise rows</th></tr>
 *   <tr><td>{@code productId}, {@code assetId}</td><td>filtered</td><td>filtered the same way</td></tr>
 *   <tr><td>{@code itemType}</td><td>excluded unless {@code VULNERABILITY}</td><td>excluded unless {@code COMPROMISE}</td></tr>
 *   <tr><td>{@code reason}</td><td>excluded unless it is one of the three alert reasons</td>
 *       <td>excluded unless {@code COMPROMISE}</td></tr>
 *   <tr><td>{@code confidence}</td><td><b>all excluded</b></td><td>filtered</td></tr>
 *   <tr><td>{@code minCvss}, {@code fixState}, {@code minExploitMaturity}, {@code matchConfidence}</td>
 *       <td>filtered</td><td><b>all excluded</b></td></tr>
 * </table>
 *
 * @param productId          only items on SBOMs belonging to this product. Never matches an
 *                           asset-derived item, even one whose asset is linked to that product — see
 *                           {@code ActionableItemResponse.assetId}.
 * @param assetId            only items a scanner raised against this asset's components.
 *                           <b>Behaviour change in Phase 4:</b> Phase 1 and 2 documented this
 *                           parameter as accepted-and-ignored, because there was no {@code Asset}
 *                           entity for it to match. There is one now and the filter is real, so a
 *                           caller that was passing an arbitrary UUID and relying on it being a no-op
 *                           will now get an empty page instead of the unfiltered list.
 * @param reason             exact {@link ActionableReason}. Note {@code KEV_AND_EPSS_HIGH} is its
 *                           own value — filtering on {@code KEV} does not include it. Filtering on
 *                           {@code COMPROMISE} is equivalent to {@code itemType=COMPROMISE}.
 * @param minCvss            CVSS base score at or above this. Items whose CVE has no score are
 *                           excluded, since "unscored" is not "below the bar".
 * @param state              exact {@link net.jdesive.secy.persistence.entity.TriageState} name
 *                           (OPEN / ACKNOWLEDGED / SNOOZED / RESOLVED / FALSE_POSITIVE), for both
 *                           arms. Null (the default) applies the Phase 7 default-list behavior
 *                           instead of an exact match: hide {@code RESOLVED}, hide
 *                           {@code FALSE_POSITIVE}, and hide {@code SNOOZED} rows whose snooze has
 *                           not yet expired — a snooze past its expiry reappears automatically. This
 *                           is a string, not a {@code TriageState}, so an old client that always sends
 *                           it still round-trips a value the server does not recognise. <b>Not</b> the
 *                           lifecycle state — both arms already restrict to {@code ACTIVE}
 *                           unconditionally regardless of this filter.
 * @param fixState           exact {@link FixState}
 * @param minExploitMaturity {@link ExploitMaturity} at or above this, by the enum's declaration
 *                           order. {@code NONE} is a no-op since everything is at least NONE.
 * @param matchConfidence    exact {@link MatchConfidence}, mirroring {@code fixState}. Filtering to
 *                           {@code EXACT} is how an operator asks for "only what I am certain
 *                           about"; there is deliberately no "at or above" form, because the useful
 *                           question in practice is the exact band.
 * @param itemType           which arm of the union to return. Null returns both, which is the
 *                           primary screen's default.
 * @param confidence         exact {@link CompromiseConfidence}. The compromise-side analogue of
 *                           {@code matchConfidence}, and exact for the same reason.
 */
public record ActionableFilter(
        UUID productId,
        UUID assetId,
        ActionableReason reason,
        Double minCvss,
        String state,
        FixState fixState,
        ExploitMaturity minExploitMaturity,
        MatchConfidence matchConfidence,
        ActionableItemType itemType,
        CompromiseConfidence confidence) {

    /**
     * Whether any vulnerability row could satisfy this filter.
     *
     * <p>False short-circuits the alert query entirely rather than running it and discarding the
     * result — and, importantly, keeps it out of the {@code totalElements} count.
     */
    public boolean includesVulnerabilities() {
        return itemType != ActionableItemType.COMPROMISE
                && reason != ActionableReason.COMPROMISE
                && confidence == null;
    }

    /** Whether any compromise row could satisfy this filter. See {@link #includesVulnerabilities()}. */
    public boolean includesCompromises() {
        return itemType != ActionableItemType.VULNERABILITY
                && (reason == null || reason == ActionableReason.COMPROMISE)
                && minCvss == null
                && fixState == null
                && matchConfidence == null
                && (minExploitMaturity == null || minExploitMaturity == ExploitMaturity.NONE);
    }

}
