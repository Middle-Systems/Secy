package net.jdesive.secy.model.compromise;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One compromise finding, in full — both a row of {@code GET /compromise} and the body of
 * {@code GET /compromise/{id}}.
 *
 * <h2>Why list and detail are the same shape</h2>
 *
 * <p>{@code /actionable} splits them ({@code ActionableItemResponse} vs
 * {@code ActionableDetailResponse}) because a CVE detail pulls in the full NVD record, every other
 * component the CVE affects, the KEV entry, the EPSS entry and the reference list — far too much to
 * put on every row of a table. A compromise finding has none of that. Its "detail" is the feed's
 * write-up and its provenance, which is two extra strings. Splitting it would cost a second type and
 * a second endpoint to save a couple of hundred bytes per row.
 *
 * @param id                  the finding id
 * @param type                {@code MALICIOUS_PACKAGE} / {@code MALWARE_HASH}
 * @param confidence          {@code CONFIRMED} / {@code LIKELY} / {@code INVESTIGATE}
 * @param severity            always {@code CRITICAL} — fixed, not configurable, see {@link CompromiseFinding}
 * @param source              the feed name
 * @param iocId               the feed's id for the indicator — a {@code MAL-…} id, or the SHA-256
 * @param matchedOn           what of yours matched: the component's PURL, or the digest
 * @param summary             the feed's one-line description
 * @param details             the feed's write-up — for a malicious package this is the analyst
 *                            evidence, and is the most useful thing in the drawer. Null for a hash
 * @param origins             who reported it: the malicious-packages origin sources, or the
 *                            MalwareBazaar submitter
 * @param referencesJson      the feed record's {@code references[]} array, verbatim JSON. Null when
 *                            the record carried none. Passed through unparsed on purpose — it is
 *                            rendered, never queried
 * @param iocFirstSeen        when the feed first saw the indicator
 * @param iocLastSeen         when the feed last saw it — what IOC aging measures against
 * @param iocConfidence       the feed's own 0–1 conviction, when it states one
 * @param agedAt              when IOC aging demoted this finding, or null if it never has. A non-null
 *                            value next to {@code confidence = INVESTIGATE} is how the UI explains
 *                            <em>why</em> a finding is only worth investigating
 * @param lifecycleState      {@code ACTIVE} / {@code AUTO_RESOLVED}. Only {@code ACTIVE} rows are
 *                            returned by default
 * @param productId           the product the affected SBOM belongs to. Null on an asset finding
 * @param productName         that product's name
 * @param assetId             the asset a scanner found this on. Null on an SBOM finding. Exactly one
 *                            of {@code productId}/{@code assetId} is normally set
 * @param assetName           that asset's name
 * @param componentId         the affected component — an {@code sbom_component} or {@code asset_component} id
 * @param componentName       component name
 * @param componentVersion    the version observed
 * @param componentPurl       component PURL, when it has one
 * @param createdAt           when the finding was first raised
 * @param lastSeenAt          when detection last reproduced it
 */
public record CompromiseFindingResponse(
        UUID id,
        CompromiseType type,
        CompromiseConfidence confidence,
        String severity,
        String source,
        String iocId,
        String matchedOn,
        String summary,
        String details,
        String origins,
        String referencesJson,
        LocalDateTime iocFirstSeen,
        LocalDateTime iocLastSeen,
        Double iocConfidence,
        LocalDateTime agedAt,
        AlertLifecycleState lifecycleState,
        UUID productId,
        String productName,
        UUID assetId,
        String assetName,
        UUID componentId,
        String componentName,
        String componentVersion,
        String componentPurl,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt) {
}
