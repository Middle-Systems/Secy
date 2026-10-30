package net.jdesive.secy.model.actionitem;

/**
 * How many of an action item's remaining findings have a known fix versus don't — M1k's
 * "Concrete fix" rollup (ROADMAP.md, "Role-based views" §5). Counts the exact same "remaining"
 * population {@code ActionItemResponse.remainingFindingCount} does. "Known fix" means a
 * {@code VULNERABILITY} finding with {@code fixState == FIXED}; every other remaining finding
 * (including every non-vulnerability type, which has no fix-state concept at all) counts as
 * without a known fix.
 */
public record ActionItemFixSummary(long remainingWithKnownFix, long remainingWithoutKnownFix) {
}
