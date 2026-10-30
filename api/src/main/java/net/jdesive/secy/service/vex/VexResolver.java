package net.jdesive.secy.service.vex;

import net.jdesive.secy.model.vex.VexStatementRole;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Pure resolution over one alert's applicable {@link VexStatement}s — no Spring, no persistence, no
 * side effects, so it can be unit-tested directly and reused unchanged by both
 * {@code VexResolutionService.applyTo} (correlation-time) and {@code explain} (the detail endpoint).
 *
 * <p>The algorithm, in the order it runs:
 *
 * <ol>
 *   <li><b>Applicable.</b> A statement applies when its {@code matchKey} equals the target's identity
 *       key, its {@code matchVersion} is null or equal to the target's observed version (loosely — see
 *       {@link #versionsEqual}), and its {@code scopeProductId} is null or equals the target's product.
 *       Nothing applicable resolves to {@link VexResolution#NONE}.</li>
 *   <li><b>Author supersession.</b> Applicable statements are grouped by {@code (origin, authorKey)};
 *       within a group, the newest (by statement timestamp, then row creation, then document ordinal,
 *       then id, all descending) is <em>current</em> and the rest are {@link VexStatementRole#SUPERSEDED}
 *       — moving from {@code under_investigation} to {@code not_affected} over time is normal lifecycle,
 *       not a conflict.</li>
 *   <li><b>Tiers.</b> {@link VexPrecedencePolicy#tierOrder()} is walked in order; the first origin with
 *       at least one current statement is the winning tier. Every current statement from a later tier
 *       is {@link VexStatementRole#OVERRIDDEN} — precedence, never a conflict.</li>
 *   <li><b>Winning tier.</b> One distinct status among the tier's current statements: the newest is
 *       {@link VexStatementRole#WON}, the rest {@link VexStatementRole#AGREES}, and the resolution takes
 *       the winner's status/justification. More than one distinct status: every current statement in
 *       the tier is {@link VexStatementRole#CONFLICTING} and the resolution is empty — "flag, don't
 *       guess" (M1c's rule).</li>
 * </ol>
 */
public final class VexResolver {

    private VexResolver() {
    }

    /**
     * @param identityKey the correlatable component's identity key
     * @param version     the observed version, preferably the PURL's own — null matches every
     *                    version-pinned-null statement, but never a version-pinned statement
     * @param productId   the SBOM product's id for an SBOM-derived alert, null for an asset-derived one
     */
    public record AlertTarget(String cveId, String identityKey, String version, UUID productId) {
    }

    public record VexResolution(VexStatus status, VexJustification justification, UUID winningStatementId,
                                boolean conflict, Map<UUID, VexStatementRole> roles) {

        public static final VexResolution NONE = new VexResolution(null, null, null, false, Map.of());
    }

    public static VexResolution resolve(AlertTarget target, List<VexStatement> candidates, VexPrecedencePolicy policy) {
        List<VexStatement> applicable = candidates.stream().filter(s -> isApplicable(s, target)).toList();
        if (applicable.isEmpty()) {
            return VexResolution.NONE;
        }

        // Group by (origin, authorKey); within a group, newest first.
        Map<String, List<VexStatement>> byAuthor = new LinkedHashMap<>();
        for (VexStatement statement : applicable) {
            String key = statement.getOrigin() + "\u0000" + statement.getAuthorKey();
            byAuthor.computeIfAbsent(key, k -> new ArrayList<>()).add(statement);
        }

        Comparator<VexStatement> newestFirst = Comparator
                .comparing(VexStatement::getStatementTimestamp, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(VexStatement::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing((VexStatement s) -> s.getOrdinal(), Comparator.reverseOrder())
                .thenComparing(s -> s.getId().toString(), Comparator.reverseOrder());

        Map<UUID, VexStatementRole> roles = new LinkedHashMap<>();
        Map<VexOrigin, List<VexStatement>> currentByOrigin = new LinkedHashMap<>();

        for (List<VexStatement> group : byAuthor.values()) {
            List<VexStatement> sorted = group.stream().sorted(newestFirst).toList();
            VexStatement current = sorted.get(0);
            for (int i = 1; i < sorted.size(); i++) {
                roles.put(sorted.get(i).getId(), VexStatementRole.SUPERSEDED);
            }
            currentByOrigin.computeIfAbsent(current.getOrigin(), o -> new ArrayList<>()).add(current);
        }

        VexOrigin winningTier = null;
        for (VexOrigin origin : policy.tierOrder()) {
            if (currentByOrigin.containsKey(origin) && !currentByOrigin.get(origin).isEmpty()) {
                winningTier = origin;
                break;
            }
        }

        for (Map.Entry<VexOrigin, List<VexStatement>> entry : currentByOrigin.entrySet()) {
            if (!entry.getKey().equals(winningTier)) {
                for (VexStatement statement : entry.getValue()) {
                    roles.put(statement.getId(), VexStatementRole.OVERRIDDEN);
                }
            }
        }

        if (winningTier == null) {
            // Every current statement was already claimed by a tier not walked at all — cannot happen
            // since tierOrder() covers both VexOrigin values, but guards against a future third origin.
            return new VexResolution(null, null, null, false, roles);
        }

        List<VexStatement> tierCurrent = currentByOrigin.get(winningTier).stream().sorted(newestFirst).toList();
        long distinctStatuses = tierCurrent.stream().map(VexStatement::getStatus).distinct().count();

        if (distinctStatuses > 1) {
            for (VexStatement statement : tierCurrent) {
                roles.put(statement.getId(), VexStatementRole.CONFLICTING);
            }
            return new VexResolution(null, null, null, true, roles);
        }

        VexStatement winner = tierCurrent.get(0);
        roles.put(winner.getId(), VexStatementRole.WON);
        for (int i = 1; i < tierCurrent.size(); i++) {
            roles.put(tierCurrent.get(i).getId(), VexStatementRole.AGREES);
        }

        return new VexResolution(winner.getStatus(), winner.getJustification(), winner.getId(), false, roles);
    }

    private static boolean isApplicable(VexStatement statement, AlertTarget target) {
        if (statement.getMatchKey() == null || !statement.getMatchKey().equals(target.identityKey())) {
            return false;
        }
        if (statement.getMatchVersion() != null && !versionsEqual(statement.getMatchVersion(), target.version())) {
            return false;
        }
        return statement.getScopeProductId() == null || Objects.equals(statement.getScopeProductId(), target.productId());
    }

    /** Loose equality: trims both, strips one leading {@code v}/{@code V} before a digit, case-insensitive. */
    private static boolean versionsEqual(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return stripV(a.trim()).equalsIgnoreCase(stripV(b.trim()));
    }

    private static String stripV(String value) {
        if (value.length() > 1 && (value.charAt(0) == 'v' || value.charAt(0) == 'V') && Character.isDigit(value.charAt(1))) {
            return value.substring(1);
        }
        return value;
    }

}
