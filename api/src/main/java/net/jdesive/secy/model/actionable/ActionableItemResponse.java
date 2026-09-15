package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /actionable} — a <b>typed union</b> since Phase 6.
 *
 * <h2>Why one flat record and not two nested ones</h2>
 *
 * <p>Phase 6 added a third promotion path whose rows are not {@code VulnerabilityAlert}s at all, so
 * the list had to carry two kinds of thing. Three shapes were on the table:
 *
 * <ol>
 *   <li><b>Two endpoints.</b> Rejected outright: the roadmap's whole point is that the operator sees
 *       one ranked list of what to do next, and a compromise finding outranks every CVE on it.
 *       Two lists means the operator does the merging, which is the job.</li>
 *   <li><b>A nested envelope</b> — {@code {itemType, vulnerability: {…}, compromise: {…}}}. Clean on
 *       paper, and it breaks every existing client: the UI's table, the asset drill-down and the
 *       compliance view all read {@code row.cveId} today.</li>
 *   <li><b>A flat envelope with a discriminator</b> — this. Every Phase 1-5 field keeps its exact
 *       JSON path and meaning, three genuinely shared fields are populated for both arms, and the
 *       compromise-only fields are added alongside, null on a vulnerability row. Nothing that reads
 *       this endpoint today has to change; a client that wants the new arm switches on
 *       {@link #itemType}.</li>
 * </ol>
 *
 * <h2>Which fields belong to which arm</h2>
 *
 * <table border="1">
 *   <caption>Field population by {@code itemType}</caption>
 *   <tr><th>Fields</th><th>{@code VULNERABILITY}</th><th>{@code COMPROMISE}</th></tr>
 *   <tr><td>{@code id}, {@code itemType}, {@code createdAt}</td><td>set</td><td>set</td></tr>
 *   <tr><td>{@code description}, {@code baseSeverity}, {@code actionableReason}</td>
 *       <td>from the CVE / funnel</td><td>the finding's summary, always {@code CRITICAL}, always {@code COMPROMISE}</td></tr>
 *   <tr><td>component + scope: {@code productId}/{@code productName}/{@code assetId}/{@code assetName}/
 *           {@code componentId}/{@code componentName}/{@code componentVersion}/{@code componentPurl}</td>
 *       <td>set</td><td>set — same meaning, same XOR between product and asset</td></tr>
 *   <tr><td>{@code cveId}, {@code cvssScore}, {@code epssScore}, {@code epssPercentile}, {@code kev},
 *           {@code kevDueDate}, {@code knownRansomwareUse}, {@code exploitMaturity}, {@code fixState},
 *           {@code fixedVersions}, {@code fixSource}, {@code matchConfidence}</td>
 *       <td>set</td><td><b>null</b> ({@code kev} is {@code false}, {@code exploitMaturity} null)</td></tr>
 *   <tr><td>{@code compromiseType}, {@code compromiseConfidence}, {@code compromiseSource},
 *           {@code iocId}, {@code matchedOn}, {@code iocFirstSeen}, {@code iocLastSeen},
 *           {@code iocConfidence}</td>
 *       <td><b>null</b></td><td>set</td></tr>
 * </table>
 *
 * <h2>The detail hop</h2>
 *
 * <p>{@link #id} is the id of whichever row this is, and the two arms have <b>different detail
 * endpoints</b>: {@code GET /actionable/{id}} for {@code VULNERABILITY} (it returns the full CVE, the
 * other components it affects, and the KEV/EPSS evidence — none of which a compromise finding has),
 * {@code GET /compromise/{id}} for {@code COMPROMISE}. Passing a compromise id to
 * {@code /actionable/{id}} returns 404 rather than a half-empty CVE detail.
 *
 * @param id                   the row id — see the detail-hop note above
 * @param itemType             the discriminator. Never null
 * @param cveId                e.g. {@code CVE-2021-44228}. Null on a compromise row, which has no CVE
 * @param description          CVE description (truncated) or, on a compromise row, the finding's summary
 * @param baseSeverity         NVD severity band, or {@code CRITICAL} on every compromise row
 * @param cvssScore            CVSS base score, null when NVD has not scored the CVE
 * @param epssScore            EPSS probability 0–1, null when the CVE has no EPSS row
 * @param epssPercentile       EPSS percentile 0–1, null when the CVE has no EPSS row
 * @param kev                  whether the CVE is on the CISA KEV catalog; always false on a compromise row
 * @param kevDueDate           CISA remediation deadline; null unless KEV-listed
 * @param knownRansomwareUse   KEV's verdict verbatim — "Known" / "Unknown" / null
 * @param exploitMaturity      NONE / POC / WEAPONIZED / IN_THE_WILD
 * @param fixState             FIXED / NO_FIX / UNKNOWN. Null on a compromise row: malware is not
 *                             "fixed" in a later version, it is removed
 * @param fixedVersions        fixed version(s) when {@code fixState = FIXED}
 * @param fixSource            where {@code fixedVersions} came from
 * @param matchConfidence      how firmly correlation identified the affected component —
 *                             {@code EXACT} / {@code RANGE} / {@code HEURISTIC}. Null on a compromise
 *                             row, which reports {@code compromiseConfidence} instead
 * @param actionableReason     which limb of the funnel promoted this row. {@code COMPROMISE} on a
 *                             compromise row — see {@link ActionableReason#COMPROMISE}
 * @param productId            the product the affected SBOM belongs to. Null on an asset row
 * @param productName          that product's name
 * @param assetId              the asset a scanner found this on. Null on an SBOM row. Exactly one of
 *                             {@code productId}/{@code assetId} is normally set, for both arms
 * @param assetName            that asset's name — image {@code repo:tag}, hostname, service name
 * @param componentId          the affected component — an {@code sbom_component} or {@code asset_component} id
 * @param componentName        component name
 * @param componentVersion     the version observed
 * @param componentPurl        component PURL; null for an OS package, which has none by design
 * @param compromiseType       {@code MALICIOUS_PACKAGE} / {@code MALWARE_HASH}. Compromise rows only
 * @param compromiseConfidence {@code CONFIRMED} / {@code LIKELY} / {@code INVESTIGATE} — and the
 *                             primary sort within the compromise tier. Compromise rows only
 * @param compromiseSource     the feed name, e.g. {@code OpenSSF Malicious Packages}
 * @param iocId                the feed's id for the indicator — a {@code MAL-…} id, or the SHA-256
 * @param matchedOn            what of yours matched: the PURL, or the digest
 * @param iocFirstSeen         when the feed first saw the indicator
 * @param iocLastSeen          when the feed last saw it — what IOC aging measures against
 * @param iocConfidence        the feed's own 0–1 conviction about the indicator, when it states one
 * @param createdAt            when the row was generated — the UI's "age" column
 */
public record ActionableItemResponse(
        UUID id,
        ActionableItemType itemType,
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
        CompromiseType compromiseType,
        CompromiseConfidence compromiseConfidence,
        String compromiseSource,
        String iocId,
        String matchedOn,
        LocalDateTime iocFirstSeen,
        LocalDateTime iocLastSeen,
        Double iocConfidence,
        LocalDateTime createdAt) {
}
