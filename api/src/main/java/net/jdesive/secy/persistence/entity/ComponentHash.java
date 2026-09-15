package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Locale;

/**
 * One cryptographic digest a document or scanner reported for a component.
 *
 * <h2>Why a generic {@code (algorithm, value)} pair and not a {@code sha256} column</h2>
 *
 * <p>Phase 6 only matches SHA-256 — that is the identifier MalwareBazaar's export is keyed on, and
 * matching a 128-bit MD5 against a malware corpus is a collision argument nobody wants to have. But
 * CycloneDX {@code hashes[]} and SPDX {@code checksums[]} both carry a <em>set</em> of algorithms
 * ({@code MD5}, {@code SHA-1}, {@code SHA-256}, {@code SHA-512}, {@code BLAKE2b-256}, …), and
 * dropping everything but one of them on the way in would mean re-parsing every stored SBOM the day
 * a second hash feed arrives. Storing what the document said costs one small child table and keeps
 * the parse lossless; the matcher reads {@link #SHA_256} and ignores the rest.
 *
 * <h2>Normalisation</h2>
 *
 * <p>{@link #algorithm} is upper-cased and {@link #value} lower-cased on construction. CycloneDX
 * spells it {@code "SHA-256"}, SPDX spells it {@code "SHA256"}, and hex digests arrive in both
 * cases; a match is an equality test, so both sides have to agree on spelling before they reach the
 * database. {@link #isSha256()} accepts either spelling.
 */
@Getter
@Setter
@Embeddable
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class ComponentHash {

    /** The canonical SHA-256 spelling Secy stores and matches on. */
    public static final String SHA_256 = "SHA-256";

    /** A SHA-256 digest is 64 hex characters. */
    public static final int SHA256_LENGTH = 64;

    /** Upper-cased algorithm name, verbatim from the document otherwise — {@code SHA-256}, {@code MD5}. */
    @Column(name = "algorithm", length = 32, nullable = false)
    private String algorithm;

    /** Lower-cased hex digest. Sized for SHA-512, the longest CycloneDX/SPDX algorithm. */
    @Column(name = "hash_value", length = 128, nullable = false)
    private String value;

    /**
     * Build a normalised hash, or {@code null} when either half is missing or the digest is not
     * hex. A malformed entry is dropped rather than stored: an unparseable digest can never match
     * anything, and keeping it would only put junk in front of an operator.
     */
    public static ComponentHash of(String algorithm, String value) {
        if (algorithm == null || algorithm.isBlank() || value == null || value.isBlank()) {
            return null;
        }
        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);
        if (normalizedValue.length() > 128 || !normalizedValue.chars().allMatch(ComponentHash::isHex)) {
            return null;
        }
        String normalizedAlgorithm = algorithm.trim().toUpperCase(Locale.ROOT);
        if (normalizedAlgorithm.length() > 32) {
            return null;
        }
        return new ComponentHash(normalizedAlgorithm, normalizedValue);
    }

    /** True for both the CycloneDX ({@code SHA-256}) and SPDX ({@code SHA256}) spellings. */
    public boolean isSha256() {
        if (algorithm == null) {
            return false;
        }
        String compact = algorithm.replace("-", "").replace("_", "");
        return "SHA256".equalsIgnoreCase(compact) && value != null && value.length() == SHA256_LENGTH;
    }

    private static boolean isHex(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }

}
