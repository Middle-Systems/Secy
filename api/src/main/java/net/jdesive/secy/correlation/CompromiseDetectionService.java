package net.jdesive.secy.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.version.VersionRange;
import net.jdesive.secy.correlation.version.VersionScheme;
import net.jdesive.secy.correlation.version.VersionSchemes;
import net.jdesive.secy.model.component.ComponentIdentity;
import net.jdesive.secy.model.component.CorrelatableComponent;
import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.MaliciousPackageRepository;
import net.jdesive.secy.persistence.MalwareHashRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.ComponentHash;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MaliciousPackageRange;
import net.jdesive.secy.persistence.entity.MalwareHash;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.service.CompromiseAgingService;
import net.jdesive.secy.service.MaliciousPackageIngestService;
import net.jdesive.secy.service.MalwareHashIngestService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Turns an SBOM or a scanned asset into {@link CompromiseFinding}s — "you are shipping something
 * known-bad", as opposed to {@link CorrelationService}'s "you have a vulnerability".
 *
 * <h2>A sibling, not an extension</h2>
 *
 * <p>This runs from inside {@code CorrelationService}, at the end of both of its correlate methods,
 * so it fires automatically on every SBOM upload, every asset scan and every compliance re-scan with
 * no separate trigger. But it is its own class, because the two engines share almost nothing below
 * the component loop: no CVE lookup, no {@code EnrichmentService}, no fix resolution, no KEV/EPSS,
 * and a completely different corpus. Folding it into {@code CorrelationService} would have doubled
 * that class's size to reuse a {@code for} loop.
 *
 * <p>What it <em>does</em> reuse is everything that identifies a component:
 * {@link ComponentCoordinate} for the ecosystem/name/version triple, {@link VersionSchemes} for
 * comparing versions the way the ecosystem does, and {@link ComponentIdentity} for the scope-stable
 * key. No version arithmetic is reimplemented here.
 *
 * <h2>The two matches</h2>
 *
 * <ol>
 *   <li><b>Malicious package</b> — {@code (ecosystem, name)} against {@code malicious_package}, then
 *       a version test. See {@link #evaluate} for the confidence rules.</li>
 *   <li><b>Malware hash</b> — the component's declared SHA-256 against {@code malware_hash}, exact
 *       equality. Every digest in a scope is looked up in one batched query, not one per component.</li>
 * </ol>
 *
 * <h2>Re-scan semantics — the same contract correlation offers</h2>
 *
 * <p>Idempotent and total within a scope, keyed on {@code (component identity, type, ioc id)}:
 * a match with no row gets one; a match that already has a row updates it in place and is set
 * {@link AlertLifecycleState#ACTIVE}; a row whose match no longer holds becomes
 * {@link AlertLifecycleState#AUTO_RESOLVED} and is <b>never deleted</b>. The scope is the product for
 * SBOM components and the asset for asset components — the Phase 3/4 split, for the same reasons
 * spelled out in {@code CorrelationService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CompromiseDetectionService {

    private final MaliciousPackageRepository maliciousPackageRepository;

    private final MalwareHashRepository malwareHashRepository;

    private final CompromiseFindingRepository findingRepository;

    /** Digest loaders — see {@link #digests} for why hashes are not read off the component entities. */
    private final SBOMComponentRepository sbomComponentRepository;

    private final AssetComponentRepository assetComponentRepository;

    private final CompromiseAgingService agingService;

    /**
     * What one detection pass did. Returned for logging and tests; nothing persists it.
     *
     * @param componentsScanned components the SBOM/scan presented
     * @param created           findings inserted
     * @param updated           existing findings refreshed (including revived ones)
     * @param autoResolved      existing findings whose match no longer holds
     */
    public record DetectionSummary(int componentsScanned, int created, int updated, int autoResolved) {

        static final DetectionSummary EMPTY = new DetectionSummary(0, 0, 0, 0);

        /** True when anything at all is being shipped that a feed calls known-bad. */
        public boolean foundAnything() {
            return created > 0 || updated > 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* SBOM                                                               */
    /* ------------------------------------------------------------------ */

    /** Detect over every component of an SBOM and reconcile the findings for its <b>product</b>. */
    @Transactional
    public DetectionSummary detect(SBOM sbom) {
        UUID sbomId = sbom.getId();
        UUID productId = sbom.getProduct() == null ? null : sbom.getProduct().getId();

        List<CompromiseFinding> prior = productId == null
                ? findingRepository.findAllBySbomIdForDetection(sbomId)
                : findingRepository.findAllByProductIdForDetection(productId);

        Map<String, SBOMComponent> componentsByIdentity = new LinkedHashMap<>();
        Map<String, UUID> rowIds = new LinkedHashMap<>();
        for (SBOMComponent component : sbom.getComponents()) {
            if (component != null && component.getId() != null) {
                String identity = identityOf(component, component.getId());
                componentsByIdentity.put(identity, component);
                rowIds.put(identity, component.getId());
            }
        }

        return reconcile("SBOM " + sbomId, prior, componentsByIdentity,
                digests(rowIds, sbomComponentRepository::findHashesByComponentIds),
                (finding, identity) -> finding.setComponent(componentsByIdentity.get(identity)));
    }

    /* ------------------------------------------------------------------ */
    /* Asset                                                              */
    /* ------------------------------------------------------------------ */

    /** Detect over a scanned asset's components and reconcile the findings for that <b>asset</b>. */
    @Transactional
    public DetectionSummary detect(Asset asset) {
        UUID assetId = asset.getId();

        List<CompromiseFinding> prior = findingRepository.findAllByAssetIdForDetection(assetId);

        Map<String, AssetComponent> componentsByIdentity = new LinkedHashMap<>();
        Map<String, UUID> rowIds = new LinkedHashMap<>();
        for (AssetComponent component : asset.getComponents()) {
            if (component != null && component.getId() != null && component.isPresentInLastScan()) {
                String identity = identityOf(component, component.getId());
                componentsByIdentity.put(identity, component);
                rowIds.put(identity, component.getId());
            }
        }

        return reconcile("asset " + assetId, prior, componentsByIdentity,
                digests(rowIds, assetComponentRepository::findHashesByComponentIds),
                (finding, identity) -> finding.setAssetComponent(componentsByIdentity.get(identity)));
    }

    /* ------------------------------------------------------------------ */
    /* Digests                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Load the scope's declared digests, re-keyed from component id to component identity.
     *
     * <p>Read through a repository rather than off {@code component.getHashes()} because the entity
     * graph handed to detection may be detached — the SBOM upload path demonstrably is. See
     * {@code CorrelatableComponent} for the full account of why hashes are not on that interface.
     *
     * <p>Re-keying here is what lets everything below {@link #matchAll} stay component-kind
     * agnostic: the loader knows which table it read, the matcher only ever sees identities. Same
     * division {@code CorrelationService} draws between its scope-specific prior-alert queries and
     * its shared {@code reconcile}.
     *
     * @param rowIds identity → component row id, for this scope
     * @param loader the repository query for this component kind
     */
    private static Map<String, List<ComponentHash>> digests(Map<String, UUID> rowIds,
                                                            Function<Collection<UUID>, List<Object[]>> loader) {
        if (rowIds.isEmpty()) {
            return Map.of();
        }
        List<Object[]> rows = loader.apply(rowIds.values());
        if (rows.isEmpty()) {
            // The common case: no SBOM generator in wide use emits hashes[], and no scanner
            // normaliser populates the asset side at all. One query, no rows, nothing allocated.
            return Map.of();
        }

        Map<UUID, String> identityByRowId = new LinkedHashMap<>();
        rowIds.forEach((identity, rowId) -> identityByRowId.put(rowId, identity));

        Map<String, List<ComponentHash>> byIdentity = new LinkedHashMap<>();
        for (Object[] row : rows) {
            String identity = identityByRowId.get((UUID) row[0]);
            if (identity == null) {
                continue;
            }
            ComponentHash hash = ComponentHash.of((String) row[1], (String) row[2]);
            if (hash != null && hash.isSha256()) {
                byIdentity.computeIfAbsent(identity, ignored -> new ArrayList<>()).add(hash);
            }
        }
        return byIdentity;
    }

    /* ------------------------------------------------------------------ */
    /* Matching                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * One matched indicator, before it becomes a row.
     *
     * @param key        the reconciliation identity
     * @param confidence what the evidence supports, before IOC aging is applied
     * @param matchedOn  the operator-recognisable value that hit — a PURL, or the digest
     * @param source     the feed name
     * @param summary    the feed's one-line description
     * @param details    the feed's write-up, when it has one
     * @param origins    who reported it
     * @param references the feed record's references, as raw JSON
     * @param firstSeen  the IOC's first-seen timestamp
     * @param lastSeen   the IOC's last-seen timestamp — what aging measures
     * @param iocConfidence the feed's own 0–1 conviction, when it expresses one
     */
    private record Indicator(FindingKey key, CompromiseConfidence confidence, String matchedOn,
                             String source, String summary, String details, String origins,
                             String references, LocalDateTime firstSeen, LocalDateTime lastSeen,
                             Double iocConfidence) {
    }

    /**
     * Run both matchers over a scope's components.
     *
     * <p>Takes {@link CorrelatableComponent}s plus a digest map keyed the same way, so it is
     * identical for SBOM and asset components — the same bargain
     * {@code CorrelationService.matchAll} strikes. The digests arrive pre-loaded rather than being
     * read off the components; see {@link #digests} for why.
     */
    private Map<FindingKey, Indicator> matchAll(Map<String, ? extends CorrelatableComponent> componentsByIdentity,
                                                Map<String, List<ComponentHash>> digestsByIdentity) {
        Map<FindingKey, Indicator> indicators = new LinkedHashMap<>();

        // Every SHA-256 in the scope, looked up once. A findById per component would be an N+1 over a
        // table that holds the whole MalwareBazaar corpus.
        Map<String, MalwareHash> malware = lookupHashes(digestsByIdentity);

        for (Map.Entry<String, ? extends CorrelatableComponent> entry : componentsByIdentity.entrySet()) {
            String identity = entry.getKey();
            CorrelatableComponent component = entry.getValue();

            matchMaliciousPackages(identity, component, indicators);
            matchMalwareHashes(identity, digestsByIdentity.get(identity), malware, indicators);
        }

        return indicators;
    }

    /** {@code (ecosystem, name)} → {@code malicious_package}, then the version test. */
    private void matchMaliciousPackages(String identity, CorrelatableComponent component,
                                        Map<FindingKey, Indicator> indicators) {
        ComponentCoordinate coordinate = ComponentCoordinate.of(component);
        if (!coordinate.hasEcosystem()) {
            // No PURL type OSV indexes means no ecosystem to look the package up in. Unlike the CVE
            // path there is no CPE fallback here: the malicious-packages corpus is keyed on
            // (ecosystem, package) and nothing else, and guessing a vendor/product for it would
            // manufacture CRITICAL findings out of a name collision. An OS package is correctly out
            // of scope for this feed.
            return;
        }

        List<MaliciousPackage> candidates =
                maliciousPackageRepository.findForPackage(coordinate.ecosystem(), coordinate.name());
        if (candidates.isEmpty()) {
            return;
        }

        VersionScheme scheme = VersionSchemes.forEcosystem(coordinate.ecosystem());
        String matchedOn = matchedOn(coordinate, component);

        for (MaliciousPackage candidate : candidates) {
            CompromiseConfidence confidence = evaluate(candidate, coordinate, scheme);
            if (confidence == null) {
                continue;
            }
            FindingKey key = new FindingKey(identity, CompromiseType.MALICIOUS_PACKAGE, candidate.getMalId());
            indicators.put(key, new Indicator(key, confidence, matchedOn,
                    MaliciousPackageIngestService.SOURCE,
                    candidate.getSummary(), candidate.getDetails(), candidate.getOrigins(),
                    candidate.getReferencesJson(), candidate.getIocFirstSeen(), candidate.getIocLastSeen(),
                    null));
        }
    }

    /**
     * Does this malicious-package record implicate this component, and how firmly?
     *
     * <p>The rules, in the order they are tested — see {@link CompromiseConfidence} for the
     * principle behind the split:
     *
     * <ol>
     *   <li><b>Withdrawn</b> → no match. The record still exists so a reversal needs no re-import,
     *       exactly as {@code OsvMatcher} treats a withdrawn advisory.</li>
     *   <li><b>The record enumerates our exact version</b> → {@code CONFIRMED}. Compared with the
     *       ecosystem's scheme rather than by string equality, so a record listing {@code 1.0} still
     *       matches an SBOM declaring {@code 1.0.0}.</li>
     *   <li><b>The record asserts the whole package is malicious</b> → {@code CONFIRMED}, whatever
     *       version we hold, <em>including none</em>. This is the common case and it needs no
     *       arithmetic: "all versions" covers whatever you have.</li>
     *   <li><b>The package matched but we have no version to test</b> → {@code LIKELY}. The name is
     *       right and we cannot rule ourselves out; reporting nothing would be a silent false
     *       negative on a malware feed, which is the wrong way to be wrong.</li>
     *   <li><b>Our version falls in a bounded stated range</b> → {@code LIKELY}. Interval arithmetic
     *       is an inference, and the record did not name our build.</li>
     *   <li>Otherwise → no match. A record that enumerates 1.0.1 does not implicate our 1.0.0.</li>
     * </ol>
     *
     * <h2>The one subtlety: whole-package ranges are skipped in the last step</h2>
     *
     * <p>Records that enumerate versions <em>also</em> carry an {@code introduced: "0"} range — the
     * real corpus does this universally, because OSV's schema wants a range and the enumeration is
     * the part the feed actually means. Letting that boilerplate range through the interval check
     * would make step 4 match <b>every</b> version of the package, quietly undoing step 2's whole
     * purpose and condemning the clean 1.0.0 of a package whose 1.0.1 was hijacked.
     *
     * <p>So the interval check considers <em>bounded</em> ranges only. A record whose ranges are all
     * whole-package has already been answered by step 3 ({@code affectsAllVersions()} requires an
     * empty enumeration), so nothing is lost: the two steps partition the cases rather than
     * overlapping.
     *
     * @return the confidence, or null when this record does not implicate the component
     */
    private static CompromiseConfidence evaluate(MaliciousPackage candidate, ComponentCoordinate coordinate,
                                                 VersionScheme scheme) {
        if (!candidate.isCurrent()) {
            return null;
        }

        String version = coordinate.version();
        boolean versioned = coordinate.isVersioned();

        if (versioned && candidate.getVersions() != null && candidate.getVersions().stream()
                .anyMatch(listed -> scheme.contains(version, VersionRange.exact(listed)))) {
            return CompromiseConfidence.CONFIRMED;
        }

        if (candidate.affectsAllVersions()) {
            return CompromiseConfidence.CONFIRMED;
        }

        if (!versioned) {
            return CompromiseConfidence.LIKELY;
        }

        for (MaliciousPackageRange range : candidate.getRanges()) {
            // GIT ranges carry commit hashes, not versions. Whole-package ranges are the schema
            // boilerplate that accompanies an enumeration — see the class note above; matching on one
            // here would make every version of an enumerated record a hit.
            if (!range.isEvaluable() || range.isWholePackage()) {
                continue;
            }
            if (scheme.contains(version,
                    VersionRange.osv(range.getIntroduced(), range.getFixed(), range.getLastAffected()))) {
                return CompromiseConfidence.LIKELY;
            }
        }

        return null;
    }

    /** Component SHA-256 → {@code malware_hash}, exact equality. */
    private void matchMalwareHashes(String identity, List<ComponentHash> componentDigests,
                                    Map<String, MalwareHash> malware,
                                    Map<FindingKey, Indicator> indicators) {
        if (malware.isEmpty() || componentDigests == null || componentDigests.isEmpty()) {
            return;
        }
        for (ComponentHash hash : componentDigests) {
            MalwareHash sample = malware.get(hash.getValue());
            if (sample == null) {
                continue;
            }
            FindingKey key = new FindingKey(identity, CompromiseType.MALWARE_HASH, sample.getSha256());
            indicators.put(key, new Indicator(key,
                    // A digest equality is the strongest statement Secy can make about anything: the
                    // bytes you ship are the bytes somebody submitted as malware. No inference, so
                    // CONFIRMED unconditionally — subject only to IOC aging, like every other finding.
                    CompromiseConfidence.CONFIRMED,
                    sample.getSha256(),
                    MalwareHashIngestService.SOURCE,
                    summaryOf(sample), null, sample.getReporter(), null,
                    sample.getFirstSeen(), sample.getLastSeen(), sample.getConfidence()));
        }
    }

    /** Every SHA-256 across the scope, in one query against the malware corpus. */
    private Map<String, MalwareHash> lookupHashes(Map<String, List<ComponentHash>> digestsByIdentity) {
        if (digestsByIdentity.isEmpty()) {
            return Map.of();
        }
        Set<String> digests = new LinkedHashSet<>();
        for (List<ComponentHash> hashes : digestsByIdentity.values()) {
            for (ComponentHash hash : hashes) {
                digests.add(hash.getValue());
            }
        }
        if (digests.isEmpty()) {
            return Map.of();
        }
        Map<String, MalwareHash> byDigest = new LinkedHashMap<>();
        for (MalwareHash sample : malwareHashRepository.findAllBySha256In(digests)) {
            byDigest.put(sample.getSha256(), sample);
        }
        return byDigest;
    }

    private static String summaryOf(MalwareHash sample) {
        if (sample.getSignature() != null) {
            return "Known malware sample: " + sample.getSignature();
        }
        return "Known malware sample (unlabelled) reported to MalwareBazaar";
    }

    /**
     * The value the finding reports as "what of yours matched" — the PURL when the component has
     * one, the ecosystem-native coordinate when it does not.
     */
    private static String matchedOn(ComponentCoordinate coordinate, CorrelatableComponent component) {
        if (coordinate.purl() != null) {
            return truncate(coordinate.purl(), 512);
        }
        StringBuilder out = new StringBuilder();
        out.append(coordinate.ecosystem()).append('/').append(coordinate.name());
        String version = component.getVersion();
        if (version != null && !version.isBlank()) {
            out.append('@').append(version.trim());
        }
        return truncate(out.toString(), 512);
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * The shared upsert-and-auto-resolve pass — the compromise twin of
     * {@code CorrelationService.reconcile}, and deliberately the same shape so the two behave
     * identically on a re-scan.
     *
     * @param attach points a finding at the component row that currently supports it
     */
    private DetectionSummary reconcile(String scopeLabel,
                                       Collection<CompromiseFinding> prior,
                                       Map<String, ? extends CorrelatableComponent> componentsByIdentity,
                                       Map<String, List<ComponentHash>> digestsByIdentity,
                                       BiConsumer<CompromiseFinding, String> attach) {
        Map<FindingKey, Indicator> indicators = matchAll(componentsByIdentity, digestsByIdentity);

        Map<FindingKey, CompromiseFinding> existing = new LinkedHashMap<>();
        for (CompromiseFinding finding : prior) {
            existing.putIfAbsent(FindingKey.of(finding), finding);
        }

        if (indicators.isEmpty() && existing.isEmpty()) {
            return DetectionSummary.EMPTY;
        }

        LocalDateTime now = LocalDateTime.now();
        List<CompromiseFinding> toSave = new ArrayList<>();
        int created = 0;
        int updated = 0;

        for (Map.Entry<FindingKey, Indicator> entry : indicators.entrySet()) {
            FindingKey key = entry.getKey();
            Indicator indicator = entry.getValue();

            CompromiseFinding finding = existing.get(key);
            if (finding == null) {
                finding = new CompromiseFinding();
                finding.setCreatedAt(now);
                created++;
            } else {
                updated++;
            }

            attach.accept(finding, key.componentIdentity());

            finding.setType(key.type());
            finding.setIocId(truncate(key.iocId(), 255));
            finding.setSource(truncate(indicator.source(), 255));
            finding.setMatchedOn(indicator.matchedOn());
            finding.setSummary(truncate(indicator.summary(), 1024));
            finding.setDetails(truncate(indicator.details(), 10024));
            finding.setOrigins(truncate(indicator.origins(), 512));
            finding.setReferencesJson(truncate(indicator.references(), 4096));
            finding.setIocFirstSeen(indicator.firstSeen());
            finding.setIocLastSeen(indicator.lastSeen());
            finding.setIocConfidence(indicator.iocConfidence());
            finding.setSeverity(CompromiseFinding.SEVERITY);
            finding.setLifecycleState(AlertLifecycleState.ACTIVE);
            finding.setLastSeenAt(now);

            // Evidence first, then the one staleness rule both this and the nightly sweep obey. A
            // re-derived CONFIRMED on a three-year-old IOC is demoted right back here rather than
            // flip-flopping with CompromiseAgingService — see that class.
            finding.setConfidence(indicator.confidence());
            finding.setAgedAt(null);
            agingService.applyAging(finding, now);

            toSave.add(finding);
        }

        int autoResolved = 0;
        for (Map.Entry<FindingKey, CompromiseFinding> entry : existing.entrySet()) {
            if (indicators.containsKey(entry.getKey())) {
                continue;
            }
            CompromiseFinding stale = entry.getValue();
            if (stale.getLifecycleState() == AlertLifecycleState.AUTO_RESOLVED) {
                continue;
            }
            stale.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            toSave.add(stale);
            autoResolved++;
        }

        if (!toSave.isEmpty()) {
            findingRepository.saveAll(toSave);
        }

        DetectionSummary summary =
                new DetectionSummary(componentsByIdentity.size(), created, updated, autoResolved);
        if (summary.foundAnything() || autoResolved > 0) {
            log.warn("Compromise detection on {}: {}", scopeLabel, summary);
        } else {
            log.debug("Compromise detection on {}: {}", scopeLabel, summary);
        }
        return summary;
    }

    /**
     * The identity of a finding: one row per affected component <em>identity</em> per indicator,
     * within the scope that produced it.
     *
     * <p>{@code type} is part of the key rather than implied by {@code iocId} so a package that is
     * both a {@code MAL-} record and ships a known-malware file produces two findings — they are two
     * separate facts with two separate pieces of evidence, and collapsing them would lose one.
     */
    private record FindingKey(String componentIdentity, CompromiseType type, String iocId) {

        static FindingKey of(CompromiseFinding finding) {
            CorrelatableComponent component = finding.getCorrelatableComponent();
            UUID rowId = finding.getComponent() != null
                    ? finding.getComponent().getId()
                    : (finding.getAssetComponent() == null ? null : finding.getAssetComponent().getId());
            return new FindingKey(
                    component == null ? null : identityOf(component, rowId),
                    finding.getType(),
                    finding.getIocId());
        }
    }

    /** See {@code CorrelationService.identityOf} — same key, same fallback, same reason. */
    private static String identityOf(CorrelatableComponent component, UUID rowId) {
        String key = ComponentIdentity.keyOf(component.getPurl(), component.getName());
        return key != null ? key : "id/" + rowId;
    }

    private static String truncate(String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        return value.substring(0, max);
    }

}
