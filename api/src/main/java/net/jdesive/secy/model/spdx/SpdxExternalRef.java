package net.jdesive.secy.model.spdx;

import lombok.Data;

/**
 * An SPDX {@code externalRefs[]} entry.
 *
 * <p>{@code referenceCategory} is {@code PACKAGE-MANAGER} / {@code SECURITY} / {@code OTHER}
 * (SPDX 2.2 spelled the first {@code PACKAGE_MANAGER}); {@code referenceType} is {@code purl},
 * {@code cpe23Type}, {@code advisory}, … and {@code referenceLocator} is the value.
 */
@Data
public class SpdxExternalRef {

    private String referenceCategory;

    private String referenceType;

    private String referenceLocator;

    private String comment;

}
