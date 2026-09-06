package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /actionable}: everything the Actionable Items table renders, and nothing
 * that would drag a Hibernate proxy into the response.
 *
 * @param id                 the alert id — pass to {@code GET /actionable/{id}}
 * @param cveId              e.g. {@code CVE-2021-44228}
 * @param description        CVE description, truncated for the table
 * @param baseSeverity       NVD severity band ({@code CRITICAL} / {@code HIGH} / …), may be null
 * @param cvssScore          CVSS base score, null when NVD has not scored the CVE
 * @param epssScore          EPSS probability 0–1, null when the CVE has no EPSS row
 * @param epssPercentile     EPSS percentile 0–1, null when the CVE has no EPSS row
 * @param kev                whether the CVE is on the CISA KEV catalog
 * @param kevDueDate         CISA remediation deadline; null unless KEV-listed
 * @param knownRansomwareUse KEV's verdict verbatim — "Known" / "Unknown" / null
 * @param exploitMaturity    NONE / POC / WEAPONIZED / IN_THE_WILD
 * @param fixState           FIXED / NO_FIX / UNKNOWN
 * @param fixedVersions      fixed version(s) when {@code fixState = FIXED}
 * @param fixSource          where {@code fixedVersions} came from
 * @param actionableReason   which limb of the funnel promoted this row
 * @param productId          the product the affected SBOM belongs to, null for an orphan SBOM
 * @param productName        that product's name
 * @param componentId        the affected SBOM component
 * @param componentName      component name
 * @param componentVersion   component version as declared in the SBOM
 * @param componentPurl      component PURL
 * @param createdAt          when the alert was generated — the UI's "age" column
 */
public record ActionableItemResponse(
        UUID id,
        String cveId,
        String description,
        String baseSeverity,
        Double cvssScore,
        Double epssScore,
        Double epssPercentile,
        boolean kev,
        LocalDate kevDueDate,
        String knownRansomwareUse,
        ExploitMaturity exploitMaturity,
        FixState fixState,
        String fixedVersions,
        FixSource fixSource,
        ActionableReason actionableReason,
        UUID productId,
        String productName,
        UUID componentId,
        String componentName,
        String componentVersion,
        String componentPurl,
        LocalDateTime createdAt) {
}
