package net.jdesive.secy.correlation.version;

import org.apache.maven.artifact.versioning.ComparableVersion;

/**
 * Maven / Gradle version ordering.
 *
 * <p>Delegates to Maven's own {@code ComparableVersion}, because Maven version precedence is not
 * defined by a specification — it is defined by that class. Its rules are genuinely surprising
 * (qualifier ranking {@code alpha < beta < milestone < rc = cr < snapshot < "" = final = ga < sp},
 * unknown qualifiers sorting <em>above</em> the release, {@code 1.0} equal to {@code 1.0.0} equal to
 * {@code 1}, and {@code -} versus {@code .} separators producing different nesting) and any
 * reimplementation would diverge on exactly the versions that matter. It costs one 58 KB jar with
 * no transitive dependencies; see {@code build.gradle}.
 *
 * <p>Two Maven-specific notes for anyone reading a match:
 *
 * <ul>
 *   <li>{@code 1.0-SNAPSHOT < 1.0}, so an OSV range fixed at {@code 1.0} still covers the snapshot
 *       that preceded it.</li>
 *   <li>{@code 2.17.1 > 2.17.0} but also {@code 2.17.1 > 2.17.1-rc1} — the Log4Shell fix versions
 *       people actually check.</li>
 * </ul>
 *
 * <p>The <em>package</em> name for this ecosystem is {@code groupId:artifactId}, which is
 * {@code ComponentCoordinate}'s job, not this class's.
 */
public final class MavenScheme implements VersionScheme {

    static final MavenScheme INSTANCE = new MavenScheme();

    MavenScheme() {
    }

    @Override
    public String name() {
        return "maven";
    }

    @Override
    public int compare(String a, String b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? 0 : -1) : 1;
        }
        try {
            return new ComparableVersion(a.trim()).compareTo(new ComparableVersion(b.trim()));
        } catch (RuntimeException e) {
            // ComparableVersion is documented as total, but the contract of VersionScheme is that a
            // scan never dies on one bad version string.
            return GenericScheme.INSTANCE.compare(a, b);
        }
    }

}
