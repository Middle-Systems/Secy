package net.jdesive.secy.model.spdx;

import lombok.Data;

/**
 * One entry of an SPDX package's {@code checksums[]}.
 *
 * <p>SPDX shape is {@code {"algorithm": "SHA256", "checksumValue": "<hex>"}} — note the algorithm
 * spelling has no hyphen, unlike CycloneDX's {@code SHA-256}.
 * {@code ComponentHash.isSha256()} accepts both so the two parsers converge on one stored form.
 */
@Data
public class SpdxChecksum {

    /** {@code SHA256}, {@code SHA1}, {@code MD5}, … */
    private String algorithm;

    /** The hex digest. */
    private String checksumValue;

}
