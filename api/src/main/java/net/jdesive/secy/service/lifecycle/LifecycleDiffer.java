package net.jdesive.secy.service.lifecycle;

import net.jdesive.secy.model.lifecycle.StageComponent;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The pure Source/Build/Analyzed/Deployed diff engine (M1e, ROADMAP.md — "SBOM lifecycle stages +
 * diffing"). No Spring, no JPA — same style as {@code ComponentIdentityAssessor}: a static function
 * from two component sets to a diff result, so it is trivial to unit test exhaustively and trivial
 * for {@code LifecycleDiffService} to wire up against real repositories.
 *
 * <h2>What "baseline" and "observed" mean</h2>
 *
 * <p>{@code baseline} is the upstream stage in a {@link net.jdesive.secy.persistence.entity.LifecycleStagePair}
 * (what the pair's earlier stage declared); {@code observed} is the downstream stage (what actually
 * showed up later). The unifying rule across every pair: raise a finding when the downstream SBOM
 * contains something the upstream SBOM never vouched for — an extra component, or a concrete version
 * the upstream SBOM did not declare.
 *
 * <h2>Steps</h2>
 *
 * <ol>
 *   <li>Drop components with a null identity key — they cannot be carried forward or compared.</li>
 *   <li>Group by identity key. One SBOM can have several rows per identity (the known
 *       {@code ComponentIdentity} collapse); each group keeps its set of normalized concrete versions
 *       plus one representative row, chosen deterministically (lowest {@code componentId}).</li>
 *   <li><b>Ecosystem coverage scoping</b> (deliberate noise control): the ecosystem is the identity
 *       key's prefix before its first {@code /} ({@code npm}, {@code maven}, {@code deb}, {@code name}
 *       for a PURL-less identity). An observed identity is only compared if the baseline SBOM has at
 *       least one identity in the same ecosystem — an app-only Build SBOM that never inventoried the
 *       OS layer should not have every {@code deb} package in a Deployed image scan flagged as
 *       "unauthorized". The same rule applies in reverse for a would-be REMOVED identity. Skipped
 *       identities are counted, not silently dropped.</li>
 *   <li>Classify:
 *     <ul>
 *       <li><b>{@code UNEXPECTED_COMPONENT}</b> — in observed, not in baseline, covered ecosystem.</li>
 *       <li><b>REMOVED</b> — in baseline, not in observed. Computed and counted (see
 *           {@link LifecycleDiff#removedIdentityKeys()}) but <b>never</b> becomes a finding — a
 *           deliberate policy choice (see the per-pair table on {@code LifecycleDiffService}), kept in
 *           this output so enabling it later is a one-line policy change, not a re-derivation.</li>
 *       <li><b>{@code VERSION_MISMATCH}</b> — in both, baseline has at least one concrete version,
 *           observed has at least one concrete version, and {@code observedConcrete \ baselineConcrete}
 *           is non-empty.</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <h2>Version normalization and "concrete"</h2>
 *
 * <p>A version is normalized by trimming, lower-casing, and stripping one leading {@code v} when
 * followed by a digit (so {@code v1.2.3} and {@code 1.2.3} are the same version). A version is
 * "concrete" when it is non-blank, not one of {@code unknown}/{@code latest}/{@code *}, contains none
 * of {@code ^ ~ < > = * | ,} or a space, and has no bare {@code x}/{@code X} wildcard segment
 * (matching {@code (^|\.)[xX](\.|$)}) — a manifest range like {@code ^4.17.0} never produces a false
 * mismatch this way.
 */
public final class LifecycleDiffer {

    private static final Pattern RANGE_CHARACTERS = Pattern.compile("[\\^~<>=*|, ]");
    private static final Pattern WILDCARD_SEGMENT = Pattern.compile("(^|\\.)[xX](\\.|$)");

    private LifecycleDiffer() {
    }

    /** One disagreement, before it becomes a {@link net.jdesive.secy.persistence.entity.LifecycleDriftFinding}. */
    public record Drift(String identityKey, StageComponent representative,
                        SortedSet<String> observedVersions, SortedSet<String> baselineVersions) {
    }

    /**
     * The whole diff result for one adjacent stage pair.
     *
     * @param unexpected         {@code UNEXPECTED_COMPONENT} candidates
     * @param versionMismatches  {@code VERSION_MISMATCH} candidates
     * @param removedIdentityKeys identities present in baseline, absent from observed — computed,
     *                           never raised as a finding (see the class Javadoc)
     * @param outOfCoverage      identities skipped because their ecosystem had no counterpart on the
     *                           other side, in either direction
     */
    public record LifecycleDiff(List<Drift> unexpected, List<Drift> versionMismatches,
                                List<String> removedIdentityKeys, int outOfCoverage) {
    }

    /** One identity's collapsed view of a component set. */
    private record Group(StageComponent representative, SortedSet<String> concreteVersions) {
    }

    public static LifecycleDiff diff(Collection<StageComponent> baseline, Collection<StageComponent> observed) {
        Map<String, Group> baselineGroups = groupByIdentity(baseline);
        Map<String, Group> observedGroups = groupByIdentity(observed);

        java.util.Set<String> baselineEcosystems = ecosystemsOf(baselineGroups.keySet());
        java.util.Set<String> observedEcosystems = ecosystemsOf(observedGroups.keySet());

        List<Drift> unexpected = new ArrayList<>();
        List<Drift> versionMismatches = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        int outOfCoverage = 0;

        for (Map.Entry<String, Group> entry : observedGroups.entrySet()) {
            String identity = entry.getKey();
            Group observedGroup = entry.getValue();
            Group baselineGroup = baselineGroups.get(identity);

            if (baselineGroup == null) {
                if (!baselineEcosystems.contains(ecosystemOf(identity))) {
                    outOfCoverage++;
                    continue;
                }
                unexpected.add(new Drift(identity, observedGroup.representative(),
                        observedGroup.concreteVersions(), new TreeSet<>()));
                continue;
            }

            if (!baselineGroup.concreteVersions().isEmpty() && !observedGroup.concreteVersions().isEmpty()) {
                SortedSet<String> extra = new TreeSet<>(observedGroup.concreteVersions());
                extra.removeAll(baselineGroup.concreteVersions());
                if (!extra.isEmpty()) {
                    versionMismatches.add(new Drift(identity, observedGroup.representative(),
                            observedGroup.concreteVersions(), baselineGroup.concreteVersions()));
                }
            }
        }

        for (String identity : baselineGroups.keySet()) {
            if (observedGroups.containsKey(identity)) {
                continue;
            }
            if (!observedEcosystems.contains(ecosystemOf(identity))) {
                outOfCoverage++;
                continue;
            }
            removed.add(identity);
        }

        return new LifecycleDiff(unexpected, versionMismatches, removed, outOfCoverage);
    }

    /* ------------------------------------------------------------------ */

    private static Map<String, Group> groupByIdentity(Collection<StageComponent> components) {
        Map<String, List<StageComponent>> byIdentity = new LinkedHashMap<>();
        for (StageComponent component : components) {
            if (component == null || component.identityKey() == null) {
                continue;
            }
            byIdentity.computeIfAbsent(component.identityKey(), k -> new ArrayList<>()).add(component);
        }

        Map<String, Group> groups = new LinkedHashMap<>();
        for (Map.Entry<String, List<StageComponent>> entry : byIdentity.entrySet()) {
            List<StageComponent> rows = entry.getValue();
            StageComponent representative = rows.stream()
                    .min(Comparator.comparing(c -> c.componentId() == null ? "" : c.componentId().toString()))
                    .orElse(rows.get(0));

            SortedSet<String> concrete = new TreeSet<>();
            for (StageComponent row : rows) {
                String normalized = normalize(row.version());
                if (isConcrete(normalized)) {
                    concrete.add(normalized);
                }
            }
            groups.put(entry.getKey(), new Group(representative, concrete));
        }
        return groups;
    }

    private static java.util.Set<String> ecosystemsOf(Collection<String> identityKeys) {
        java.util.Set<String> ecosystems = new java.util.LinkedHashSet<>();
        for (String key : identityKeys) {
            ecosystems.add(ecosystemOf(key));
        }
        return ecosystems;
    }

    /** The identity key's ecosystem: the prefix before its first {@code /}. */
    private static String ecosystemOf(String identityKey) {
        int slash = identityKey.indexOf('/');
        return slash < 0 ? identityKey : identityKey.substring(0, slash);
    }

    private static String normalize(String version) {
        if (version == null) {
            return "";
        }
        String trimmed = version.trim().toLowerCase(Locale.ROOT);
        if (trimmed.length() > 1 && trimmed.charAt(0) == 'v' && Character.isDigit(trimmed.charAt(1))) {
            trimmed = trimmed.substring(1);
        }
        return trimmed;
    }

    private static boolean isConcrete(String normalizedVersion) {
        if (normalizedVersion == null || normalizedVersion.isBlank()) {
            return false;
        }
        if (normalizedVersion.equals("unknown") || normalizedVersion.equals("latest")
                || normalizedVersion.equals("*")) {
            return false;
        }
        if (RANGE_CHARACTERS.matcher(normalizedVersion).find()) {
            return false;
        }
        return !WILDCARD_SEGMENT.matcher(normalizedVersion).find();
    }

}
