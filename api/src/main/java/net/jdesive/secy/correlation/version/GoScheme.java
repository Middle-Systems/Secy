package net.jdesive.secy.correlation.version;

/**
 * Go module version ordering.
 *
 * <p>Go versions <em>are</em> SemVer, wrapped in two conventions this class unwraps before handing
 * the string to {@link SemVerScheme}:
 *
 * <ul>
 *   <li><b>The mandatory {@code v} prefix.</b> {@code v1.2.3}, never {@code 1.2.3}. OSV's Go ranges
 *       drop it ({@code introduced: "1.2.3"}) while {@code go.mod} and most SBOM generators keep it,
 *       so the two must compare equal.</li>
 *   <li><b>{@code +incompatible}.</b> A pre-modules major version reached through the compatibility
 *       shim. SemVer treats anything after {@code +} as build metadata and ignores it, which is the
 *       correct ordering here too — {@code v3.0.0+incompatible} and {@code v3.0.0} are the same
 *       release.</li>
 * </ul>
 *
 * <p>Pseudo-versions ({@code v0.0.0-20191109021931-daa7c04131f5}) need no special handling: the
 * timestamp-plus-hash after the dash is a SemVer pre-release, so a pseudo-version sorts below the
 * tagged release it precedes, and two pseudo-versions on the same base sort by their fixed-width
 * timestamps. That is exactly Go's own rule.
 *
 * <p>The {@code /v2} major-version suffix lives in the <em>module path</em>, not the version, so it
 * is the package name's problem — see {@code ComponentCoordinate}.
 */
public final class GoScheme extends SemVerScheme {

    static final GoScheme INSTANCE = new GoScheme();

    GoScheme() {
    }

    @Override
    public String name() {
        return "go";
    }

    @Override
    protected String normalize(String version) {
        String normalized = version.trim();
        if (normalized.length() > 1
                && (normalized.charAt(0) == 'v' || normalized.charAt(0) == 'V')
                && Character.isDigit(normalized.charAt(1))) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

}
