package net.jdesive.secy.persistence.entity;

/**
 * Whether a fixed version is known for the affected component.
 *
 * <p>Phase 1 only ever produces {@link #UNKNOWN} (nothing supplies fix data yet) or {@link #FIXED}
 * when a scanner handed us a fixed version. {@link #NO_FIX} — "the upstream project has published
 * no fix" — needs OSV/distro data and arrives in Phase 2.
 */
public enum FixState {

    /** A fixed version exists; see {@code fixedVersions} / {@code fixSource}. */
    FIXED,

    /** The source that would know says no fix has been published. */
    NO_FIX,

    /** Nothing has told us either way. */
    UNKNOWN

}
