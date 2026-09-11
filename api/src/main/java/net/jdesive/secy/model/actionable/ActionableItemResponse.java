package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;

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
 * @param matchConfidence    how firmly correlation identified the affected component —
 *                           {@code EXACT} (an advisory named this exact version), {@code RANGE}
 *                           (the package was identified and its version fell in a stated range) or
 *                           {@code HEURISTIC} (the package was matched by a name guess, or by a CPE
 *                           row whose version field is an unbounded wildcard). Null only on rows
 *                           written before Phase 2.
 * @param actionableReason   which limb of the funnel promoted this row
 * @param productId          the product the affected SBOM belongs to. Null on an asset row, and on a
 *                           product row whose SBOM is orphaned.
 * @param productName        that product's name
 * @param assetId            the asset a scanner found this on (Phase 4). Null on an SBOM row.
 *                           <b>Exactly one of {@code productId}/{@code assetId} is normally set</b> —
 *                           an alert cites either an SBOM component or an asset component, never
 *                           both. An asset that happens to be linked to a product still reports only
 *                           {@code assetId} here: the finding is on the running artefact, not in the
 *                           product's declared inventory.
 * @param assetName          that asset's name — image {@code repo:tag}, hostname, service name
 * @param componentId        the affected component — an {@code sbom_component} id on a product row,
 *                           an {@code asset_component} id on an asset row
 * @param componentName      component name
 * @param componentVersion   the version observed: declared in the SBOM, or installed on the asset
 * @param componentPurl      component PURL; null for an OS package, which has none by design
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
        MatchConfidence matchConfidence,
        ActionableReason actionableReason,
        UUID productId,
        String productName,
        UUID assetId,
        String assetName,
        UUID componentId,
        String componentName,
        String componentVersion,
        String componentPurl,
        LocalDateTime createdAt) {
}
