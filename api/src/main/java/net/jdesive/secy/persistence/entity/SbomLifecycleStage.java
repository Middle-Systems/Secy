package net.jdesive.secy.persistence.entity;

/**
 * Where in the SDLC an {@link SBOM} was captured (M1e, ROADMAP.md — "SBOM lifecycle stages +
 * diffing").
 *
 * <p><b>Reserved for M1e — nothing in M1c writes this field.</b> The column exists now, nullable, so
 * M1e needs no further migration (the same no-retrofit precedent M1b set for {@code asset_id} on
 * {@code ownership_link}). {@code null} means "stage unknown", not "SOURCE" or any other default.
 */
public enum SbomLifecycleStage {
    SOURCE,
    BUILD,
    ANALYZED,
    DEPLOYED
}
