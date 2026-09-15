package net.jdesive.secy.persistence.entity;

/**
 * What kind of known-bad thing a {@link CompromiseFinding} matched.
 *
 * <p>Phase 6's whole premise is that "you have a vulnerability" and "you are shipping something
 * known-bad" are different statements about different evidence, so the kind of evidence is on the
 * row rather than inferred from which columns happen to be filled.
 */
public enum CompromiseType {

    /**
     * A component matched an OpenSSF Malicious Packages ({@code MAL-…}) record by ecosystem and
     * package name. The package itself is the malware; there is no CVE and nothing to patch — the
     * remediation is removal.
     */
    MALICIOUS_PACKAGE,

    /**
     * A component's SHA-256 file digest matched an abuse.ch MalwareBazaar sample. The artefact
     * shipped <em>is</em> a sample someone has submitted as malware.
     */
    MALWARE_HASH

}
