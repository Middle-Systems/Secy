package net.jdesive.secy.model.vex;

/**
 * How one applicable {@code VexStatement} factored into a {@code VexResolution} — computed fresh by
 * {@code VexResolver} on every resolution, never persisted.
 */
public enum VexStatementRole {

    /** The newest current statement in the winning tier — its status/justification is the resolution. */
    WON,

    /** A current statement in the winning tier that agrees with the one that WON. */
    AGREES,

    /** A current statement in the winning tier that disagrees with another — nothing wins when this appears. */
    CONFLICTING,

    /** A current statement, but in a tier precedence didn't pick. */
    OVERRIDDEN,

    /** An older statement from an author whose newer statement (WON/AGREES/CONFLICTING/OVERRIDDEN) supersedes it. */
    SUPERSEDED

}
