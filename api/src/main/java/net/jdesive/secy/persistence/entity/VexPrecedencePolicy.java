package net.jdesive.secy.persistence.entity;

import net.jdesive.secy.service.vex.InvalidVexUploadException;

import java.util.List;

/**
 * Per-tenant policy for which {@link VexOrigin} wins when both a tenant and a vendor have issued a
 * statement about the same (CVE, component) — {@code GET}/{@code PUT /vex/settings/precedence}.
 *
 * <p>Only these two ship in M1f. A future "most-recent-statement-wins across origins" policy is
 * deliberately deferred — see the M1f ROADMAP status note.
 */
public enum VexPrecedencePolicy {

    /** The tenant's own statement wins over a vendor's for the same target — the default. */
    TENANT_OVER_VENDOR,

    /** A vendor's statement wins over the tenant's own for the same target. */
    VENDOR_OVER_TENANT;

    /** The tiers to walk, most-preferred first — see {@code VexResolver}, step 3. */
    public List<VexOrigin> tierOrder() {
        return this == TENANT_OVER_VENDOR
                ? List.of(VexOrigin.TENANT, VexOrigin.VENDOR)
                : List.of(VexOrigin.VENDOR, VexOrigin.TENANT);
    }

    /**
     * Parses {@code PUT /vex/settings/precedence}'s {@code policy} field, case-insensitively.
     *
     * @throws InvalidVexUploadException when {@code raw} is null, blank, or not one of the two values
     */
    public static VexPrecedencePolicy fromApiValue(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidVexUploadException("policy is required: TENANT_OVER_VENDOR or VENDOR_OVER_TENANT");
        }
        String trimmed = raw.trim();
        for (VexPrecedencePolicy policy : values()) {
            if (policy.name().equalsIgnoreCase(trimmed)) {
                return policy;
            }
        }
        throw new InvalidVexUploadException(
                "Unknown policy '" + raw + "' — expected TENANT_OVER_VENDOR or VENDOR_OVER_TENANT");
    }

}
