package net.jdesive.secy.model.cyclonedx;

import lombok.Data;

/**
 * One entry of a CycloneDX component's {@code hashes[]}.
 *
 * <p>The spec's shape is {@code {"alg": "SHA-256", "content": "<hex>"}}, with {@code alg} drawn from
 * a fixed enumeration ({@code MD5}, {@code SHA-1}, {@code SHA-256}, {@code SHA-384},
 * {@code SHA-512}, {@code SHA3-*}, {@code BLAKE2b-*}, {@code BLAKE3}). Bound as free strings rather
 * than an enum: an unknown algorithm from a newer spec revision should normalise to a stored,
 * unmatched hash rather than fail the whole document.
 */
@Data
public class CycloneDXHash {

    /** {@code SHA-256}, {@code MD5}, … */
    private String alg;

    /** The hex digest. */
    private String content;

}
