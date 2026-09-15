package net.jdesive.secy.model.actionable;

/**
 * The discriminator of the {@code GET /actionable} typed union.
 *
 * <p>{@code GET /actionable} is the primary screen and, from Phase 6, it answers two different
 * questions at once: "which of my vulnerabilities matter" and "am I shipping something known-bad".
 * Those are backed by two tables with no join between them — {@code vulnerability_alert} and
 * {@code compromise_finding} — so a row has to say which it is before a client can read the rest of
 * it.
 *
 * <p>The field is <b>always present and never null</b> on every row, including on rows that existed
 * before Phase 6. A client that ignores it reads a compromise row as a vulnerability row with a null
 * {@code cveId}, which is wrong but not dangerous; a client that switches on it gets the right
 * fields. See {@code ActionableItemResponse} for which fields belong to which arm.
 */
public enum ActionableItemType {

    /** A {@code vulnerability_alert} row: a CVE against a component. Detail at {@code GET /actionable/{id}}. */
    VULNERABILITY,

    /** A {@code compromise_finding} row: a known-bad artefact. Detail at {@code GET /compromise/{id}}. */
    COMPROMISE

}
