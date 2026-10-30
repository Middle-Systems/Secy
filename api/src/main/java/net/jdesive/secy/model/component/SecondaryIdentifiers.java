package net.jdesive.secy.model.component;

import net.jdesive.secy.correlation.Cpe23;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Builds {@link NormalizedComponent.Identifier}s from the raw CPE/SWID fields each SBOM format
 * carries (M1c, ROADMAP.md — "Canonical component identity"). Used by {@code CycloneDXNormalizer}
 * and {@code SpdxNormalizer}; has no Spring/JPA dependency so it stays unit-testable the same way
 * the normalizers themselves are.
 */
public final class SecondaryIdentifiers {

    /** Matches {@code sbom_component_identifier.identifier_value} — an over-long value is dropped, not truncated (see {@link net.jdesive.secy.persistence.entity.ComponentHash#of}'s rule). */
    private static final int MAX_VALUE_LENGTH = 1024;

    private static final int MAX_DECLARED_LENGTH = 255;

    private static final String CPE_23_PREFIX = "cpe:2.3:";
    private static final String CPE_22_PREFIX = "cpe:/";
    private static final String SWID_PREFIX = "swid:";

    public static final String CDX_CPE = "cyclonedx:component.cpe";
    public static final String CDX_SWID = "cyclonedx:component.swid";
    public static final String SPDX_CPE23 = "spdx:externalRefs.cpe23Type";
    public static final String SPDX_CPE22 = "spdx:externalRefs.cpe22Type";
    public static final String SPDX_SWID = "spdx:externalRefs.swid";

    private SecondaryIdentifiers() {
    }

    /**
     * A declared CPE (2.2 or 2.3), or null when {@code raw} is blank, over-long, or not one of the
     * two recognised CPE spellings. The value is stored lower-cased — CPE is case-insensitive by
     * specification. Only a 2.3-formatted string with a concrete version yields
     * {@code declaredName}/{@code declaredVersion}; a 2.2 URI is stored but not further parsed (it
     * is deprecated and not worth a converter yet — see {@code ComponentIdentityAssessor}, which
     * likewise does not assess 2.2 rows).
     */
    public static NormalizedComponent.Identifier cpe(String raw, String source) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty() || trimmed.length() > MAX_VALUE_LENGTH) {
            return null;
        }
        boolean isV23 = trimmed.regionMatches(true, 0, CPE_23_PREFIX, 0, CPE_23_PREFIX.length());
        boolean isV22 = !isV23 && trimmed.regionMatches(true, 0, CPE_22_PREFIX, 0, CPE_22_PREFIX.length());
        if (!isV23 && !isV22) {
            return null;
        }

        String value = trimmed.toLowerCase(Locale.ROOT);
        String declaredName = null;
        String declaredVersion = null;

        Optional<Cpe23> parsed = Cpe23.parse(trimmed);
        if (parsed.isPresent() && parsed.get().hasConcreteVersion()) {
            declaredName = truncate(parsed.get().product(), MAX_DECLARED_LENGTH);
            declaredVersion = truncate(parsed.get().version(), MAX_DECLARED_LENGTH);
        }

        return new NormalizedComponent.Identifier(
                SecondaryIdentifierType.CPE, value, declaredName, declaredVersion, source);
    }

    /**
     * A declared SWID identifier, or null when {@code tagId} is blank (after stripping an optional
     * {@code swid:} prefix) or over-long. Unlike a CPE, the value is kept verbatim — SWID tagIds are
     * URIs/GUIDs and are not case-insensitive by any spec.
     */
    public static NormalizedComponent.Identifier swid(String tagId, String name, String version, String source) {
        if (tagId == null) {
            return null;
        }
        String trimmed = tagId.trim();
        if (trimmed.regionMatches(true, 0, SWID_PREFIX, 0, SWID_PREFIX.length())) {
            trimmed = trimmed.substring(SWID_PREFIX.length()).trim();
        }
        if (trimmed.isEmpty() || trimmed.length() > MAX_VALUE_LENGTH) {
            return null;
        }

        return new NormalizedComponent.Identifier(
                SecondaryIdentifierType.SWID, trimmed,
                truncate(trimToNull(name), MAX_DECLARED_LENGTH),
                truncate(trimToNull(version), MAX_DECLARED_LENGTH),
                source);
    }

    /** Dedupe on {@code (type, value)}, first occurrence wins, document order kept. Nulls are dropped. */
    public static List<NormalizedComponent.Identifier> dedupe(List<NormalizedComponent.Identifier> identifiers) {
        if (identifiers == null || identifiers.isEmpty()) {
            return List.of();
        }
        Set<String> seen = new LinkedHashSet<>();
        List<NormalizedComponent.Identifier> out = new ArrayList<>();
        for (NormalizedComponent.Identifier identifier : identifiers) {
            if (identifier == null) {
                continue;
            }
            String key = identifier.type() + "\u0000" + identifier.value();
            if (seen.add(key)) {
                out.add(identifier);
            }
        }
        return out;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
