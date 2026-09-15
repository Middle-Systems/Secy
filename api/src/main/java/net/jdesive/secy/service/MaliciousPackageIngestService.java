package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.CompromiseProperties;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.MaliciousPackageRepository;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MaliciousPackageRange;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Mirrors OpenSSF Malicious Packages ({@code ossf/malicious-packages}) into
 * {@code malicious_package} / {@code malicious_package_range} / {@code malicious_package_version}.
 *
 * <h2>Where the data actually comes from — what the investigation found</h2>
 *
 * <p>The roadmap says this "reuses the Phase 2 OSV ingester almost verbatim", and structurally it
 * does: one zip, one JSON document per record, OSV schema 1.5/1.6, the same
 * {@code affected[].ranges[].events[]} flattening. Three things differ, and they are why this is its
 * own class rather than a second ecosystem list on {@link OsvIngestService}:
 *
 * <ol>
 *   <li><b>There is no per-ecosystem GCS export.</b> OSSF publishes only the git repository; the
 *       records reach the world through OSV.dev, which folds them into its ordinary per-ecosystem
 *       {@code all.zip}. Measured at the time of writing, {@code npm/all.zip} is 215 MB containing
 *       228,981 records of which <b>221,577 are {@code MAL-}</b> — the malicious-package corpus
 *       dwarfs the advisory corpus it is mixed into. So the source here is GitHub's
 *       {@code codeload} archive of the repository, whose {@code osv/malicious/&lt;ecosystem&gt;/&lt;package&gt;/MAL-*.json}
 *       layout lets {@code secy.compromise.ecosystems} be honoured by path, before any JSON is
 *       parsed. Roughly 310 MB, ~479k entries.</li>
 *   <li><b>There is no {@code modified}-based cursor.</b> A repository archive has no per-ecosystem
 *       high-water mark to advance and no {@code Last-Modified} per record that survives the
 *       download, so unlike {@link OsvIngestService} this is a <b>full refresh</b> every run — the
 *       same shape {@code CveListIngestService} settled on for the CVE List bulk snapshot, and for
 *       the same reason.</li>
 *   <li><b>There is no category.</b> The roadmap anticipated typo-squat / dependency-confusion
 *       classification. The published records do not carry one — every record's CWE is
 *       {@code CWE-506 "Embedded Malicious Code"} and nothing distinguishes the attack shape
 *       structurally. What the data <em>does</em> have is
 *       {@code database_specific.malicious-packages-origins[]}, an array of
 *       {@code {source, sha256, id, import_time, modified_time, versions}} naming which scanner
 *       reported it ({@code ghsa-malware}, {@code amazon-inspector}, {@code checkmarx},
 *       {@code ossf-package-analysis}). Those become {@code origins}, and their timestamps become
 *       {@code iocFirstSeen}/{@code iocLastSeen} — which is what IOC aging needs and a category would
 *       not have supplied.</li>
 * </ol>
 *
 * <p><b>Coded defensively about the layout.</b> Any {@code .json} entry under a path containing
 * {@code osv/} is considered, the ecosystem filter is applied to the path segment after
 * {@code malicious/} when there is one and skipped when there is not, and an entry under
 * {@code withdrawn/} or {@code unmergable/} is treated as withdrawn rather than dropped. A flat zip
 * of bare {@code MAL-*.json} files — which is what a GCS-style export would look like if OSSF ever
 * publishes one — ingests correctly with no code change; only the ecosystem pre-filter goes idle.
 *
 * <p>A record that fails to parse is logged and skipped; it must not abort the archive.
 */
@Slf4j
@Service
public class MaliciousPackageIngestService {

    /** Human-readable feed name, copied onto every {@code CompromiseFinding} this feed raises. */
    public static final String SOURCE = "OpenSSF Malicious Packages";

    /** Report progress (and check for cancellation) every this many records examined. */
    private static final int PROGRESS_EVERY = 500;

    /** Path segment that marks a record the upstream has retracted. */
    private static final String WITHDRAWN_SEGMENT = "/withdrawn/";

    /**
     * Path segment that marks a report the upstream could not merge into a canonical record. Kept
     * out entirely rather than stored withdrawn: an unmergable report has no agreed package identity,
     * which is the one thing detection needs.
     */
    private static final String UNMERGABLE_SEGMENT = "/unmergable/";

    private static final String MALICIOUS_SEGMENT = "/malicious/";

    private final MaliciousPackageRepository repository;

    private final RestTemplate restTemplate;

    private final CompromiseProperties properties;

    private final ObjectMapper objectMapper;

    @Autowired
    public MaliciousPackageIngestService(MaliciousPackageRepository repository,
                                         RestTemplate restTemplate,
                                         CompromiseProperties properties,
                                         ObjectMapper objectMapper) {
        this.repository = repository;
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /** Browse the mirror — a nice-to-have for the UI, not used by detection. */
    public Page<MaliciousPackage> getPaged(String ecosystem, String packageName, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        return repository.search(blankToNull(ecosystem), blankToNull(packageName), pageable);
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingest() {
        return ingest(JobProgress.NOOP);
    }

    /**
     * Pull the archive and upsert every record in the configured ecosystems.
     *
     * @throws CancellationException if {@code progress} asks to stop between batches
     */
    public IngestResult ingest(JobProgress progress) {
        String url = properties.getMaliciousPackagesUrl();
        if (url == null || url.isBlank()) {
            return new IngestResult(0, "No malicious-packages source configured");
        }

        Set<String> wanted = wantedEcosystems();
        AtomicInteger examined = new AtomicInteger();
        AtomicInteger upserted = new AtomicInteger();
        AtomicInteger skipped = new AtomicInteger();

        log.info("Pulling OpenSSF Malicious Packages from {} (ecosystems: {})",
                url, wanted.isEmpty() ? "all" : wanted);

        restTemplate.execute(url, HttpMethod.GET, null, response -> {
            try (ZipInputStream zis = new ZipInputStream(response.getBody())) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName();
                    if (entry.isDirectory() || !name.toLowerCase(Locale.ROOT).endsWith(".json")) {
                        continue;
                    }
                    String path = "/" + name.replace('\\', '/');
                    if (path.contains(UNMERGABLE_SEGMENT) || !wantedPath(path, wanted)) {
                        continue;
                    }

                    byte[] data = zis.readAllBytes();
                    examined.incrementAndGet();
                    try {
                        upserted.addAndGet(processRecord(data, path.contains(WITHDRAWN_SEGMENT)));
                    } catch (Exception e) {
                        skipped.incrementAndGet();
                        log.warn("Skipping unparsable malicious-package record {}", name, e);
                    }

                    int seen = examined.get();
                    if (seen % PROGRESS_EVERY == 0) {
                        progress.report(upserted.get(),
                                "Examined " + seen + " malicious-package records…");
                        if (progress.isCancelled()) {
                            throw new CancellationException(
                                    "Malicious-packages ingest cancelled after " + seen + " records");
                        }
                    }
                }
            }
            return null;
        });

        String message = "Ingested " + upserted.get() + " malicious-package rows from "
                + examined.get() + " record(s)"
                + (skipped.get() == 0 ? "" : "; " + skipped.get() + " unparsable");
        progress.report(upserted.get(), message);
        log.info("Malicious-packages ingest complete: {}", message);
        return new IngestResult(upserted.get(), message);
    }

    /* ------------------------------------------------------------------ */
    /* Path filtering                                                     */
    /* ------------------------------------------------------------------ */

    private Set<String> wantedEcosystems() {
        Set<String> wanted = new LinkedHashSet<>();
        List<String> configured = properties.getEcosystems();
        if (configured != null) {
            for (String ecosystem : configured) {
                if (ecosystem != null && !ecosystem.isBlank()) {
                    wanted.add(ecosystem.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        return wanted;
    }

    /**
     * Whether an archive entry belongs to a configured ecosystem.
     *
     * <p>Defensive by design: an empty filter takes everything, and a path with no
     * {@code /malicious/<ecosystem>/} structure is <b>accepted</b> rather than rejected. A layout
     * this class does not recognise should cost a little extra parsing, never a silently empty
     * ingest — the record's own {@code affected[].package.ecosystem} is the authority on what
     * ecosystem it is for, and that is read either way.
     *
     * <p>Matched on a prefix so the upstream's release-qualified directories
     * ({@code vscode:open-vsx.org}) are covered by configuring {@code vscode}.
     */
    private static boolean wantedPath(String path, Set<String> wanted) {
        if (wanted.isEmpty()) {
            return true;
        }
        int at = path.indexOf(MALICIOUS_SEGMENT);
        if (at < 0) {
            return true;
        }
        int start = at + MALICIOUS_SEGMENT.length();
        int end = path.indexOf('/', start);
        if (end < 0) {
            return true;
        }
        String ecosystem = path.substring(start, end).toLowerCase(Locale.ROOT);
        return wanted.stream().anyMatch(ecosystem::startsWith);
    }

    /* ------------------------------------------------------------------ */
    /* One record                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Parse and upsert one OSV-format malicious-package document.
     *
     * @param withdrawnByPath whether the archive filed it under {@code osv/withdrawn/}
     * @return how many {@code (record, ecosystem, package)} rows it wrote
     */
    private int processRecord(byte[] data, boolean withdrawnByPath) throws java.io.IOException {
        JsonNode root = objectMapper.readTree(data);
        String malId = root.path("id").asText(null);
        if (malId == null || malId.isBlank()) {
            log.warn("Skipping malicious-package record with no id");
            return 0;
        }

        LocalDateTime modified = parseTimestamp(root.path("modified").asText(null));
        LocalDateTime published = parseTimestamp(root.path("published").asText(null));
        LocalDateTime withdrawn = parseTimestamp(root.path("withdrawn").asText(null));
        if (withdrawn == null && withdrawnByPath) {
            // Filed under osv/withdrawn/ but carrying no withdrawn timestamp. Fall back to the
            // record's own modified — the point is that the matcher must skip it, and a null
            // timestamp would leave it live.
            withdrawn = modified != null ? modified : LocalDateTime.now();
        }

        String summary = truncate(root.path("summary").asText(null), 1024);
        String details = truncate(root.path("details").asText(null), 10024);
        String category = truncate(root.path("database_specific").path("category").asText(null), 64);

        String referencesJson = null;
        JsonNode referencesNode = root.path("references");
        if (referencesNode.isArray() && !referencesNode.isEmpty()) {
            referencesJson = truncate(objectMapper.writeValueAsString(referencesNode), 4096);
        }

        Origins origins = readOrigins(root.path("database_specific").path("malicious-packages-origins"));

        JsonNode affectedArray = root.path("affected");
        if (!affectedArray.isArray() || affectedArray.isEmpty()) {
            if (withdrawn != null) {
                markWithdrawn(malId, withdrawn, modified);
            }
            return 0;
        }

        int written = 0;
        for (JsonNode affected : affectedArray) {
            JsonNode pkg = affected.path("package");
            String ecosystem = pkg.path("ecosystem").asText(null);
            String packageName = pkg.path("name").asText(null);
            if (ecosystem == null || ecosystem.isBlank() || packageName == null || packageName.isBlank()) {
                log.warn("Skipping affected entry with no package ecosystem/name for record {}", malId);
                continue;
            }
            upsert(malId, ecosystem, packageName, pkg.path("purl").asText(null),
                    summary, details, category, origins, referencesJson,
                    published, modified, withdrawn, affected);
            written++;
        }
        return written;
    }

    /**
     * Mirrors {@code OsvIngestService.markWithdrawn}: a withdrawal is recorded on whatever rows an
     * earlier run wrote, never by deleting them, so a reversal needs no re-import.
     */
    @Transactional
    void markWithdrawn(String malId, LocalDateTime withdrawn, LocalDateTime modified) {
        List<MaliciousPackage> existing = repository.findByMalId(malId);
        for (MaliciousPackage row : existing) {
            row.setWithdrawn(withdrawn);
            if (modified != null) {
                row.setModified(modified);
            }
            row.setLastIngestedAt(LocalDateTime.now());
            repository.save(row);
        }
    }

    /**
     * Upsert one {@code (malId, ecosystem, packageName)} row.
     *
     * <p>{@code @Transactional} for the same reason {@code OsvIngestService.upsertAdvisory} is: the
     * {@code versions} and {@code ranges} collections are {@code FetchType.LAZY}, so the find, the
     * rebuild and the save have to share one persistence context.
     */
    @Transactional
    void upsert(String malId, String ecosystem, String packageName, String purl,
                String summary, String details, String category, Origins origins, String referencesJson,
                LocalDateTime published, LocalDateTime modified, LocalDateTime withdrawn,
                JsonNode affected) {
        // findForUpsert, not the plain finder: this method's @Transactional is inert (it is reached
        // by self-invocation from processRecord, so no proxy applies) and the ingest itself runs
        // outside a transaction under JobRunner. The fetch join is what lets the clear-and-rebuild
        // below touch `versions` and `ranges` on a re-ingest without a live session. See the
        // repository method's note.
        MaliciousPackage row = repository
                .findForUpsert(malId, ecosystem, packageName)
                .orElseGet(MaliciousPackage::new);

        row.setMalId(malId);
        row.setEcosystem(truncate(ecosystem, 64));
        row.setPackageName(truncate(packageName, 512));
        row.setPurl(truncate(purl, 512));
        row.setSummary(summary);
        row.setDetails(details);
        row.setCategory(category);
        row.setOrigins(origins.joined());
        row.setReferencesJson(referencesJson);
        row.setPublished(published);
        row.setModified(modified);
        row.setWithdrawn(withdrawn);

        // The origins carry the real IOC timestamps; the record's own published/modified are the
        // fallback for a record that states no origins at all.
        row.setIocFirstSeen(origins.firstSeen() != null ? origins.firstSeen() : published);
        row.setIocLastSeen(origins.lastSeen() != null ? origins.lastSeen() : modified);
        row.setLastIngestedAt(LocalDateTime.now());

        row.getVersions().clear();
        for (JsonNode versionNode : affected.path("versions")) {
            String version = versionNode.asText(null);
            if (version != null && !version.isBlank()) {
                row.getVersions().add(truncate(version.trim(), 255));
            }
        }

        row.getRanges().clear();
        for (JsonNode rangeNode : affected.path("ranges")) {
            for (MaliciousPackageRange range : flattenRange(rangeNode)) {
                range.setMaliciousPackage(row);
                row.getRanges().add(range);
            }
        }

        repository.save(row);
    }

    /**
     * The same event-list flattening {@code OsvIngestService.flattenRange} performs — one row per
     * {@code introduced}, paired with whichever of {@code fixed}/{@code last_affected} closes it.
     *
     * <p>Duplicated rather than shared because the two produce different entity types with different
     * parents, and the ten lines of walk are not worth a generic factory to unify. The <em>rule</em>
     * is the one documented in {@code PHASE2-CONTRACT.md} §1.3 and must stay in step with it.
     */
    private static List<MaliciousPackageRange> flattenRange(JsonNode rangeNode) {
        String type = rangeNode.path("type").asText(null);
        List<MaliciousPackageRange> result = new ArrayList<>();
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

    private static MaliciousPackageRange newRange(String type, String introduced, String fixed,
                                                  String lastAffected) {
        MaliciousPackageRange range = new MaliciousPackageRange();
        range.setRangeType(truncate(type, 32));
        range.setIntroduced(truncate(introduced, 255));
        range.setFixed(truncate(fixed, 255));
        range.setLastAffected(truncate(lastAffected, 255));
        return range;
    }

    /* ------------------------------------------------------------------ */
    /* Origins                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * What {@code database_specific.malicious-packages-origins[]} yields: the distinct reporting
     * sources, and the time window they span.
     *
     * @param sources   distinct {@code origins[].source}, in first-seen order
     * @param firstSeen earliest {@code modified_time} (falling back to {@code import_time})
     * @param lastSeen  latest {@code modified_time} (falling back to {@code import_time})
     */
    record Origins(Set<String> sources, LocalDateTime firstSeen, LocalDateTime lastSeen) {

        static final Origins EMPTY = new Origins(Set.of(), null, null);

        String joined() {
            return sources.isEmpty() ? null : truncate(String.join(", ", sources), 512);
        }
    }

    private static Origins readOrigins(JsonNode originsNode) {
        if (originsNode == null || !originsNode.isArray() || originsNode.isEmpty()) {
            return Origins.EMPTY;
        }
        Set<String> sources = new LinkedHashSet<>();
        LocalDateTime first = null;
        LocalDateTime last = null;
        for (JsonNode origin : originsNode) {
            String source = origin.path("source").asText(null);
            if (source != null && !source.isBlank()) {
                sources.add(source.trim());
            }
            LocalDateTime at = parseTimestamp(origin.path("modified_time").asText(null));
            if (at == null) {
                at = parseTimestamp(origin.path("import_time").asText(null));
            }
            if (at != null) {
                first = (first == null || at.isBefore(first)) ? at : first;
                last = (last == null || at.isAfter(last)) ? at : last;
            }
        }
        return new Origins(sources, first, last);
    }

    /* ------------------------------------------------------------------ */
    /* Small helpers — same contracts as OsvIngestService's               */
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
                log.warn("Unparsable malicious-package timestamp: {}", value);
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

}
