package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.OsvProperties;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.OsvEcosystemCursorRepository;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.OsvEcosystemCursor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Mirrors OSV's per-ecosystem export into {@code osv_advisory} / {@code osv_affected_range} /
 * {@code osv_ecosystem_cursor}. See {@code PHASE2-CONTRACT.md} §1 for the full ingest contract this
 * class implements — field-for-field, this is the source of truth the correlation engine reads.
 *
 * <p>One zip per configured ecosystem, one JSON file per advisory inside it (OSV schema 1.6). A
 * failure pulling or parsing one ecosystem is logged and skipped — it must not prevent the others
 * from ingesting — and the per-ecosystem high-water mark ({@link OsvEcosystemCursor}) only advances
 * once that ecosystem's zip has been fully processed, so a failure mid-run leaves it exactly where it
 * was rather than skipping the remainder of the feed on the next pull.
 */
@Slf4j
@Service
public class OsvIngestService {

    /** Report progress (and check for cancellation) every this many records examined. */
    private static final int PROGRESS_EVERY = 250;

    private static final String ZIP_URL_TEMPLATE =
            "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip";

    private final OsvAdvisoryRepository osvAdvisoryRepository;

    private final OsvEcosystemCursorRepository cursorRepository;

    private final RestTemplate restTemplate;

    private final OsvProperties properties;

    private final ObjectMapper objectMapper;

    @Autowired
    public OsvIngestService(OsvAdvisoryRepository osvAdvisoryRepository,
                            OsvEcosystemCursorRepository cursorRepository,
                            RestTemplate restTemplate,
                            OsvProperties properties,
                            ObjectMapper objectMapper) {
        this.osvAdvisoryRepository = osvAdvisoryRepository;
        this.cursorRepository = cursorRepository;
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /** Browse the mirror — a small nice-to-have for the UI, not used by correlation. */
    public Page<OsvAdvisory> getPaged(String ecosystem, String packageName, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        return osvAdvisoryRepository.search(blankToNull(ecosystem), blankToNull(packageName), pageable);
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingest() {
        return ingest(JobProgress.NOOP);
    }

    /**
     * Pull every configured OSV ecosystem, reporting the running count to {@code progress}.
     *
     * @throws CancellationException if {@code progress} asks to stop between batches
     * @throws IllegalStateException if every configured ecosystem failed
     */
    public IngestResult ingest(JobProgress progress) {
        List<String> ecosystems = properties.getEcosystems();
        if (ecosystems == null || ecosystems.isEmpty()) {
            return new IngestResult(0, "No OSV ecosystems configured");
        }

        AtomicInteger totalProcessed = new AtomicInteger();
        List<String> succeeded = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        for (String ecosystem : ecosystems) {
            try {
                int count = ingestEcosystem(ecosystem, progress, totalProcessed);
                succeeded.add(ecosystem + " (" + count + ")");
            } catch (CancellationException e) {
                // A cancellation aborts the whole job, not just the ecosystem in progress.
                throw e;
            } catch (Exception e) {
                log.warn("OSV ingest failed for ecosystem {}", ecosystem, e);
                failures.add(ecosystem + ": " + describe(e));
            }
        }

        if (succeeded.isEmpty()) {
            throw new IllegalStateException(
                    "OSV ingest failed for every configured ecosystem: " + String.join("; ", failures));
        }

        String message = "Ingested " + totalProcessed.get() + " OSV records across " + succeeded.size()
                + " ecosystem(s): " + String.join(", ", succeeded)
                + (failures.isEmpty() ? "" : "; failed: " + String.join(", ", failures));
        progress.report(totalProcessed.get(), message);
        return new IngestResult(totalProcessed.get(), message);
    }

    /**
     * Download and process one ecosystem's {@code all.zip}, advancing its cursor only once every
     * entry in the zip has been handled.
     *
     * @return how many records this ecosystem's zip contained
     */
    private int ingestEcosystem(String ecosystem, JobProgress progress, AtomicInteger totalProcessed) {
        OsvEcosystemCursor cursor = cursorRepository.findById(ecosystem).orElse(null);
        LocalDateTime cursorModified = cursor != null ? cursor.getLastModified() : null;
        AtomicReference<LocalDateTime> maxModified = new AtomicReference<>(cursorModified);
        AtomicInteger recordsThisEcosystem = new AtomicInteger();

        String url = String.format(ZIP_URL_TEMPLATE, ecosystem);

        restTemplate.execute(url, HttpMethod.GET, null, response -> {
            try (ZipInputStream zis = new ZipInputStream(response.getBody())) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory() || !entry.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
                        continue;
                    }
                    byte[] data = zis.readAllBytes();
                    try {
                        processRecord(data, cursorModified, maxModified);
                    } catch (Exception e) {
                        log.warn("Skipping unparsable OSV record {} in ecosystem {}", entry.getName(), ecosystem, e);
                    }

                    recordsThisEcosystem.incrementAndGet();
                    int total = totalProcessed.incrementAndGet();
                    if (total % PROGRESS_EVERY == 0) {
                        progress.report(total, "Ingested " + total + " OSV records…");
                        if (progress.isCancelled()) {
                            throw new CancellationException("OSV ingest cancelled after " + total + " records");
                        }
                    }
                }
            }
            return null;
        });

        OsvEcosystemCursor toSave = cursor != null ? cursor : new OsvEcosystemCursor();
        toSave.setEcosystem(ecosystem);
        if (maxModified.get() != null) {
            toSave.setLastModified(maxModified.get());
        }
        toSave.setLastIngestedAt(LocalDateTime.now());
        cursorRepository.save(toSave);

        return recordsThisEcosystem.get();
    }

    /**
     * Parse and upsert one OSV advisory JSON document. Records whose {@code modified} is not
     * strictly newer than the ecosystem's cursor are skipped — but the running max is still updated
     * so the cursor genuinely reflects the newest record seen this run, not just the newest one
     * that happened to be written.
     */
    private void processRecord(byte[] data, LocalDateTime cursorModified, AtomicReference<LocalDateTime> maxModified)
            throws java.io.IOException {
        JsonNode root = objectMapper.readTree(data);
        String osvId = root.path("id").asText(null);
        if (osvId == null || osvId.isBlank()) {
            log.warn("Skipping OSV record with no id");
            return;
        }

        LocalDateTime modified = parseTimestamp(root.path("modified").asText(null));
        LocalDateTime published = parseTimestamp(root.path("published").asText(null));
        LocalDateTime withdrawn = parseTimestamp(root.path("withdrawn").asText(null));

        if (modified != null) {
            maxModified.updateAndGet(current -> current == null || modified.isAfter(current) ? modified : current);
        }

        if (cursorModified != null && modified != null && !modified.isAfter(cursorModified)) {
            return;
        }

        Set<String> aliases = new LinkedHashSet<>();
        // The record's own id resolves a lookup even when aliases[] is empty — contract §1.2.
        aliases.add(osvId);
        for (JsonNode aliasNode : root.path("aliases")) {
            String alias = aliasNode.asText(null);
            if (alias != null && !alias.isBlank()) {
                aliases.add(alias);
            }
        }

        String summary = truncate(root.path("summary").asText(null), 1024);
        String details = truncate(root.path("details").asText(null), 10024);

        String referencesJson = null;
        JsonNode referencesNode = root.path("references");
        if (referencesNode.isArray() && !referencesNode.isEmpty()) {
            referencesJson = truncate(objectMapper.writeValueAsString(referencesNode), 4096);
        }

        SeverityPick severity = pickSeverity(root.path("severity"));

        JsonNode affectedArray = root.path("affected");
        if (!affectedArray.isArray() || affectedArray.isEmpty()) {
            if (withdrawn != null) {
                markWithdrawn(osvId, withdrawn, modified);
            }
            return;
        }

        for (JsonNode affected : affectedArray) {
            JsonNode pkg = affected.path("package");
            String pkgEcosystem = pkg.path("ecosystem").asText(null);
            String pkgName = pkg.path("name").asText(null);
            if (pkgEcosystem == null || pkgEcosystem.isBlank() || pkgName == null || pkgName.isBlank()) {
                log.warn("Skipping affected entry with no package ecosystem/name for OSV record {}", osvId);
                continue;
            }
            upsertAdvisory(osvId, pkgEcosystem, pkgName, pkg.path("purl").asText(null),
                    aliases, severity, summary, details, referencesJson,
                    modified, published, withdrawn, affected);
        }
    }

    /**
     * A withdrawn record with no (or no longer any) {@code affected[]} entries still needs its
     * withdrawal reflected on whatever rows an earlier run wrote for it — the matcher skips withdrawn
     * rows rather than the ingester deleting them.
     */
    @Transactional
    void markWithdrawn(String osvId, LocalDateTime withdrawn, LocalDateTime modified) {
        List<OsvAdvisory> existing = osvAdvisoryRepository.findByOsvId(osvId);
        for (OsvAdvisory advisory : existing) {
            advisory.setWithdrawn(withdrawn);
            if (modified != null) {
                advisory.setModified(modified);
            }
            advisory.setLastIngestedAt(LocalDateTime.now());
            osvAdvisoryRepository.save(advisory);
        }
    }

    /**
     * Upsert one {@code (osvId, ecosystem, packageName)} row. Runs inside one transaction so the
     * find, the lazy-collection rebuild and the save all share a persistence context — the
     * {@code ranges}/{@code aliases}/{@code versions} collections are {@code FetchType.LAZY} and
     * would otherwise throw once the finder's own transaction closed.
     */
    @Transactional
    void upsertAdvisory(String osvId, String ecosystem, String packageName, String purl,
                        Set<String> aliases, SeverityPick severity,
                        String summary, String details, String referencesJson,
                        LocalDateTime modified, LocalDateTime published, LocalDateTime withdrawn,
                        JsonNode affected) {
        OsvAdvisory advisory = osvAdvisoryRepository
                .findByOsvIdAndEcosystemAndPackageName(osvId, ecosystem, packageName)
                .orElseGet(OsvAdvisory::new);

        advisory.setOsvId(osvId);
        advisory.setEcosystem(ecosystem);
        advisory.setPackageName(packageName);
        advisory.setPurl(purl);

        advisory.getAliases().clear();
        advisory.getAliases().addAll(aliases);

        advisory.setSeverity(severity.band());
        advisory.setCvssVector(severity.vector());
        advisory.setSummary(summary);
        advisory.setDetails(details);
        advisory.setReferencesJson(referencesJson);
        advisory.setModified(modified);
        advisory.setPublished(published);
        advisory.setWithdrawn(withdrawn);
        advisory.setLastIngestedAt(LocalDateTime.now());

        advisory.getRanges().clear();
        for (JsonNode rangeNode : affected.path("ranges")) {
            for (OsvAffectedRange range : flattenRange(rangeNode)) {
                range.setAdvisory(advisory);
                advisory.getRanges().add(range);
            }
        }

        advisory.getVersions().clear();
        for (JsonNode versionNode : affected.path("versions")) {
            String version = versionNode.asText(null);
            if (version != null && !version.isBlank()) {
                advisory.getVersions().add(version);
            }
        }

        osvAdvisoryRepository.save(advisory);
    }

    /**
     * THE ONE SIMPLIFICATION (contract §1.3): an OSV {@code ranges[].events[]} array is an ordered
     * event list, not a single interval — {@code [{introduced:"1.0"},{fixed:"1.2"},{introduced:"2.0"},
     * {fixed:"2.1"}]} describes two disjoint intervals. Walk the events and emit one row per
     * {@code introduced} paired with whichever of {@code fixed} / {@code last_affected} closes it,
     * leaving the bound null when nothing does before the next {@code introduced} or the end of the
     * list. {@code limit} events carry no version data our model stores and are ignored.
     */
    private List<OsvAffectedRange> flattenRange(JsonNode rangeNode) {
        String type = rangeNode.path("type").asText(null);
        List<OsvAffectedRange> result = new ArrayList<>();
        String currentIntroduced = null;
        boolean open = false;

        for (JsonNode event : rangeNode.path("events")) {
            if (event.has("introduced")) {
                if (open) {
                    result.add(newRange(type, currentIntroduced, null, null));
                }
                currentIntroduced = event.path("introduced").asText(null);
                open = true;
            } else if (event.has("fixed")) {
                result.add(newRange(type, currentIntroduced, event.path("fixed").asText(null), null));
                currentIntroduced = null;
                open = false;
            } else if (event.has("last_affected")) {
                result.add(newRange(type, currentIntroduced, null, event.path("last_affected").asText(null)));
                currentIntroduced = null;
                open = false;
            }
        }
        if (open) {
            result.add(newRange(type, currentIntroduced, null, null));
        }
        return result;
    }

    private static OsvAffectedRange newRange(String type, String introduced, String fixed, String lastAffected) {
        OsvAffectedRange range = new OsvAffectedRange();
        range.setRangeType(type);
        range.setIntroduced(introduced);
        range.setFixed(fixed);
        range.setLastAffected(lastAffected);
        return range;
    }

    /* ------------------------------------------------------------------ */
    /* Severity                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * The record's {@code severity} and {@code cvssVector}, picked from the highest-scoring
     * {@code severity[]} entry (contract §1.1).
     *
     * <p><b>Known simplification:</b> only CVSS v3.0/3.1 vectors are actually scored, via a base-score
     * calculator implementing the published formula. A record whose only severity entries are
     * {@code CVSS_V2}, {@code CVSS_V4} or a non-CVSS textual scale (e.g. distro severities) still gets
     * its vector/label stored as {@code cvssVector} for provenance, but {@code severity} is left null
     * rather than guessing a band from a scale this ingester does not compute against. In practice the
     * overwhelming majority of OSV records carry a {@code CVSS_V3} entry.
     */
    private SeverityPick pickSeverity(JsonNode severityArray) {
        if (severityArray == null || !severityArray.isArray()) {
            return SeverityPick.EMPTY;
        }

        double bestScore = -1;
        String bestVector = null;
        String bestBand = null;
        String fallbackVector = null;

        for (JsonNode entry : severityArray) {
            String type = entry.path("type").asText("");
            String score = entry.path("score").asText(null);
            if (score == null || score.isBlank()) {
                continue;
            }
            if (fallbackVector == null && type.toUpperCase(Locale.ROOT).startsWith("CVSS")) {
                fallbackVector = score;
            }
            if (score.startsWith("CVSS:3.")) {
                Double computed = cvssV3BaseScore(score);
                if (computed != null && computed > bestScore) {
                    bestScore = computed;
                    bestVector = score;
                    bestBand = bandFor(computed);
                }
            }
        }

        if (bestVector != null) {
            return new SeverityPick(bestBand, bestVector);
        }
        return new SeverityPick(null, fallbackVector);
    }

    /** {@code severity}/{@code cvssVector} chosen for one advisory row. */
    private record SeverityPick(String band, String vector) {
        static final SeverityPick EMPTY = new SeverityPick(null, null);
    }

    /** CVSS v3.0/3.1 base score, per the published formula. Returns {@code null} if unparsable. */
    private static Double cvssV3BaseScore(String vector) {
        Map<String, String> metrics = new HashMap<>();
        for (String part : vector.split("/")) {
            String[] kv = part.split(":", 2);
            if (kv.length == 2) {
                metrics.put(kv[0], kv[1]);
            }
        }
        if (!metrics.keySet().containsAll(List.of("AV", "AC", "PR", "UI", "S", "C", "I", "A"))) {
            return null;
        }

        try {
            boolean scopeChanged = "C".equals(metrics.get("S"));
            double av = switch (metrics.get("AV")) {
                case "N" -> 0.85;
                case "A" -> 0.62;
                case "L" -> 0.55;
                case "P" -> 0.2;
                default -> throw new IllegalArgumentException();
            };
            double ac = switch (metrics.get("AC")) {
                case "L" -> 0.77;
                case "H" -> 0.44;
                default -> throw new IllegalArgumentException();
            };
            double pr = switch (metrics.get("PR")) {
                case "N" -> 0.85;
                case "L" -> scopeChanged ? 0.68 : 0.62;
                case "H" -> scopeChanged ? 0.50 : 0.27;
                default -> throw new IllegalArgumentException();
            };
            double ui = switch (metrics.get("UI")) {
                case "N" -> 0.85;
                case "R" -> 0.62;
                default -> throw new IllegalArgumentException();
            };
            double c = impactMetric(metrics.get("C"));
            double i = impactMetric(metrics.get("I"));
            double a = impactMetric(metrics.get("A"));

            double iss = 1 - ((1 - c) * (1 - i) * (1 - a));
            double impact = scopeChanged
                    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
                    : 6.42 * iss;
            if (impact <= 0) {
                return 0.0;
            }
            double exploitability = 8.22 * av * ac * pr * ui;
            double raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
            return roundUp(Math.min(raw, 10.0));
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

    private static double impactMetric(String value) {
        return switch (value) {
            case "H" -> 0.56;
            case "L" -> 0.22;
            case "N" -> 0.0;
            default -> throw new IllegalArgumentException();
        };
    }

    /** The CVSS spec's own round-up-to-one-decimal algorithm. */
    private static double roundUp(double value) {
        long input = Math.round(value * 100000);
        if (input % 10000 == 0) {
            return input / 100000.0;
        }
        return (Math.floor(input / 10000.0) + 1) / 10.0;
    }

    private static String bandFor(double score) {
        if (score >= 9.0) {
            return "CRITICAL";
        }
        if (score >= 7.0) {
            return "HIGH";
        }
        if (score >= 4.0) {
            return "MEDIUM";
        }
        if (score > 0.0) {
            return "LOW";
        }
        return "NONE";
    }

    /* ------------------------------------------------------------------ */
    /* Small helpers                                                      */
    /* ------------------------------------------------------------------ */

    private static LocalDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.ofInstant(Instant.parse(value), ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            try {
                return OffsetDateTime.parse(value).toLocalDateTime();
            } catch (DateTimeParseException ex) {
                log.warn("Unparsable OSV timestamp: {}", value);
                return null;
            }
        }
    }

    private static String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }

    /** Exception message for the per-ecosystem failure summary, falling back to the class name. */
    private static String describe(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = root.getMessage();
        if (message == null || message.isBlank()) {
            return root.getClass().getSimpleName();
        }
        return root.getClass().getSimpleName() + ": " + message;
    }

}
