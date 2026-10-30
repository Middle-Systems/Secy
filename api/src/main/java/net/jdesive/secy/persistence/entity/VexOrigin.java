package net.jdesive.secy.persistence.entity;

import net.jdesive.secy.service.vex.InvalidVexUploadException;

import java.util.Locale;

/**
 * Who issued a VEX statement — required as an explicit {@code ?origin=} upload parameter (M1f
 * design decision #3). No document format reliably says "this is the tenant, not the vendor": OpenVEX
 * {@code author} is free text, CSAF's {@code publisher.category} values are not reliably "this
 * tenant", and CycloneDX has no such concept at all. A default here would silently decide precedence,
 * which is the whole point of {@code VexPrecedencePolicy} — so there is none.
 */
public enum VexOrigin {

    /** The tenant operating Secy issued this statement about their own product. */
    TENANT,

    /** A vendor/upstream supplier issued this statement. */
    VENDOR;

    /**
     * Parses the required {@code ?origin=} upload parameter.
     *
     * @throws InvalidVexUploadException when {@code raw} is null, blank, or not one of the two values
     */
    public static VexOrigin fromApiValue(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidVexUploadException("origin is required: TENANT or VENDOR");
        }
        String trimmed = raw.trim();
        for (VexOrigin origin : values()) {
            if (origin.name().equalsIgnoreCase(trimmed)) {
                return origin;
            }
        }
        throw new InvalidVexUploadException("Unknown origin '" + raw + "' — expected TENANT or VENDOR");
    }

}
