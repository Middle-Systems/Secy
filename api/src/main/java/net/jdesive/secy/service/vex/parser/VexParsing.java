package net.jdesive.secy.service.vex.parser;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Shared, stateless helpers for the three format parsers in this package. Package-private on
 * purpose — nothing outside {@code service.vex.parser} should need to spell a CVE regex or a PURL
 * fallback rule a second way.
 */
final class VexParsing {

    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-\\d{4}-\\d{4,}$", Pattern.CASE_INSENSITIVE);

    private static final int MAX_PURL_LENGTH = 1024;

    private VexParsing() {
    }

    /**
     * Every candidate string that is exactly a CVE id (case-insensitive), upper-cased, de-duplicated,
     * in first-seen order. Blank/null candidates are ignored.
     */
    static List<String> cveIds(String... candidates) {
        Set<String> seen = new LinkedHashSet<>();
        if (candidates != null) {
            for (String candidate : candidates) {
                if (candidate == null) {
                    continue;
                }
                String trimmed = candidate.trim();
                if (!trimmed.isEmpty() && CVE_PATTERN.matcher(trimmed).matches()) {
                    seen.add(trimmed.toUpperCase(Locale.ROOT));
                }
            }
        }
        return new ArrayList<>(seen);
    }

    /**
     * A resolved (or deliberately unmatchable) VEX target, derived from a candidate PURL string.
     *
     * @param targetPurl  the candidate string, trimmed and length-capped, kept for display/audit even
     *                    when it did not parse
     * @param matchKey    {@link ComponentIdentity#keyOf}, or null when the PURL was missing/malformed —
     *                    null means this statement can never match any alert
     * @param matchVersion the PURL's own version, or null when it declared none (matches all versions)
     */
    record PurlTarget(String targetPurl, String matchKey, String matchVersion) {

        static final PurlTarget UNMATCHABLE = new PurlTarget(null, null, null);
    }

    /**
     * Resolves a candidate PURL string into a match target. Never throws: a blank candidate, one over
     * {@value #MAX_PURL_LENGTH} characters, or one {@link PackageURL} rejects all come back
     * unmatchable (with the raw text still carried in {@link PurlTarget#targetPurl()} when it fit),
     * rather than losing the statement.
     */
    static PurlTarget purlTarget(String candidate) {
        if (candidate == null) {
            return PurlTarget.UNMATCHABLE;
        }
        String trimmed = candidate.trim();
        if (trimmed.isEmpty()) {
            return PurlTarget.UNMATCHABLE;
        }
        if (trimmed.length() > MAX_PURL_LENGTH) {
            return new PurlTarget(truncate(trimmed, MAX_PURL_LENGTH), null, null);
        }
        PackageURL parsed;
        try {
            parsed = new PackageURL(trimmed);
        } catch (MalformedPackageURLException | IllegalArgumentException e) {
            return new PurlTarget(trimmed, null, null);
        }
        String matchKey = ComponentIdentity.keyOf(trimmed, null);
        String version = parsed.getVersion() == null || parsed.getVersion().isBlank() ? null : parsed.getVersion().trim();
        return new PurlTarget(trimmed, matchKey, version);
    }

    /**
     * Parses a statement/document timestamp, tolerating both an offset (OpenVEX/CSAF/CycloneDX all
     * favor RFC 3339) and a bare local date-time. A failure is not fatal — it degrades to null (the
     * caller falls back to the document timestamp, then to ingestion time) with a warning appended.
     */
    static LocalDateTime timestamp(String raw, List<String> warnings, String context) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        try {
            return OffsetDateTime.parse(trimmed).atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
        } catch (DateTimeParseException offsetFailure) {
            try {
                return LocalDateTime.parse(trimmed);
            } catch (DateTimeParseException localFailure) {
                warnings.add("Unparseable timestamp" + (context == null ? "" : " for " + context) + ": '" + raw + "'");
                return null;
            }
        }
    }

    static String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    /**
     * A {@code NOT_AFFECTED} statement backed by no justification, no verbatim source justification
     * and no impact statement is a reasonless not-affected claim, and must never suppress an alert —
     * applied identically in every format parser.
     */
    static boolean isReasonlessNotAffected(VexStatus status, VexJustification justification,
                                           String sourceJustification, String impactStatement) {
        return status == VexStatus.NOT_AFFECTED
                && justification == null
                && (sourceJustification == null || sourceJustification.isBlank())
                && (impactStatement == null || impactStatement.isBlank());
    }

    /** The five OpenVEX justification values, shared verbatim by OpenVEX and CSAF (identical vocabulary). */
    static VexJustification openVexJustification(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "component_not_present" -> VexJustification.COMPONENT_NOT_PRESENT;
            case "vulnerable_code_not_present" -> VexJustification.VULNERABLE_CODE_NOT_PRESENT;
            case "vulnerable_code_not_in_execute_path" -> VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
            case "vulnerable_code_cannot_be_controlled_by_adversary" ->
                    VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
            case "inline_mitigations_already_exist" -> VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
            default -> null;
        };
    }

    static String joinNonBlank(String separator, String... parts) {
        StringBuilder sb = new StringBuilder();
        if (parts != null) {
            for (String part : parts) {
                if (part != null && !part.isBlank()) {
                    if (sb.length() > 0) {
                        sb.append(separator);
                    }
                    sb.append(part.trim());
                }
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

}
