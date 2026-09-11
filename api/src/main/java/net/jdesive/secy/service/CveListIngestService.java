package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.config.CveListProperties;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Ingests the CVE List v5.1 bulk snapshot (GitHub {@code CVEProject/cvelistV5}), including the
 * CISA-ADP Vulnrichment container, onto existing {@code vulnerabilities} rows. See
 * {@code PHASE2-CONTRACT.md} §2 for the field-by-field contract this class implements.
 *
 * <p><b>Full-refresh, not incremental.</b> Unlike the per-ecosystem OSV mirror there is no natural
 * high-water mark here: this is a single bulk zip covering every CVE, re-downloaded and
 * re-processed in full on each run, the same way {@code NVDService} does a full re-pull today.
 * Hourly delta ingestion (per-CVE {@code raw.githubusercontent.com} fetches) is a fast-follow, not
 * this pass.
 *
 * <p><b>Never creates a row.</b> This feed only updates a {@link Vulnerability} that
 * {@code NVDService} already created — CVE List v5 can (and often does) know about a CVE before
 * NVD's mirror does, contract §12 item 2. Several columns on {@code Vulnerability} are primitive
 * {@code double}/{@code boolean} fields NVD alone populates with real values (CVSS sub-scores,
 * privilege-escalation flags, …); minting a stub row here would either violate that data's intent by
 * writing zeros that look like real NVD-scored zeros, or require duplicating half of
 * {@code NVDService}. Skipping is the safe default — the next NVD pull picks the row up and this
 * feed's data lands on the following re-ingest.
 *
 * <p>A failure parsing one record is logged and skipped; it must not abort the whole snapshot.
 */
@Slf4j
@Service
public class CveListIngestService {

    /** Report progress (and check for cancellation) every this many records examined. */
    private static final int PROGRESS_EVERY = 250;

    private final VulnerabilityRepository vulnerabilityRepository;

    private final RestTemplate restTemplate;

    private final CveListProperties properties;

    private final ObjectMapper objectMapper;

    @Autowired
    public CveListIngestService(VulnerabilityRepository vulnerabilityRepository,
                                RestTemplate restTemplate,
                                CveListProperties properties,
                                ObjectMapper objectMapper) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingest() {
        return ingest(JobProgress.NOOP);
    }

    /**
     * Discover and pull the current bulk-snapshot zip, updating every {@link Vulnerability} row the
     * snapshot has a match for.
     *
     * @throws CancellationException if {@code progress} asks to stop between batches
     */
    public IngestResult ingest(JobProgress progress) {
        String zipUrl = resolveZipAssetUrl();

        AtomicInteger examined = new AtomicInteger();
        AtomicInteger updated = new AtomicInteger();
        AtomicInteger skippedUnknownCve = new AtomicInteger();
        AtomicInteger skippedMalformed = new AtomicInteger();

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.USER_AGENT, "secy-cve-list-ingest");

        restTemplate.execute(zipUrl, HttpMethod.GET, request -> request.getHeaders().addAll(headers), response -> {
            try (ZipInputStream zis = new ZipInputStream(response.getBody())) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory() || !entry.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
                        continue;
                    }
                    byte[] data = zis.readAllBytes();
                    try {
                        RecordOutcome outcome = processRecord(data);
                        switch (outcome) {
                            case UPDATED -> updated.incrementAndGet();
                            case SKIPPED_UNKNOWN_CVE -> skippedUnknownCve.incrementAndGet();
                            case SKIPPED_MALFORMED -> skippedMalformed.incrementAndGet();
                        }
                    } catch (Exception e) {
                        skippedMalformed.incrementAndGet();
                        log.warn("Skipping unparsable CVE List record {}", entry.getName(), e);
                    }

                    int total = examined.incrementAndGet();
                    if (total % PROGRESS_EVERY == 0) {
                        progress.report(updated.get(), "Examined " + total + " CVE List records, updated "
                                + updated.get() + "…");
                        if (progress.isCancelled()) {
                            throw new CancellationException(
                                    "CVE List ingest cancelled after " + total + " records examined");
                        }
                    }
                }
            }
            return null;
        });

        String message = "Updated " + updated.get() + " of " + examined.get() + " CVE List records ("
                + skippedUnknownCve.get() + " not yet in NVD, " + skippedMalformed.get() + " malformed)";
        progress.report(updated.get(), message);
        return new IngestResult(updated.get(), message);
    }

    /* ------------------------------------------------------------------ */
    /* Release discovery                                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Ask the GitHub releases API for the latest release and pick the first {@code .zip} asset,
     * rather than hardcoding its filename — the bulk-snapshot asset name has changed shape before
     * and this sandbox cannot confirm the current one against a live GitHub.
     */
    private String resolveZipAssetUrl() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.USER_AGENT, "secy-cve-list-ingest");
        headers.set(HttpHeaders.ACCEPT, "application/vnd.github+json");

        JsonNode release = restTemplate.exchange(
                properties.getReleasesApiUrl(), HttpMethod.GET, new HttpEntity<>(headers), JsonNode.class).getBody();

        if (release == null) {
            throw new IllegalStateException("CVE List releases API returned no body");
        }

        for (JsonNode asset : release.path("assets")) {
            String name = asset.path("name").asText("");
            if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                String url = asset.path("browser_download_url").asText(null);
                if (url != null && !url.isBlank()) {
                    return url;
                }
            }
        }

        throw new IllegalStateException(
                "No .zip asset found on the latest cvelistV5 release (" + properties.getReleasesApiUrl() + ")");
    }

    /* ------------------------------------------------------------------ */
    /* Per-record processing                                              */
    /* ------------------------------------------------------------------ */

    private enum RecordOutcome { UPDATED, SKIPPED_UNKNOWN_CVE, SKIPPED_MALFORMED }

    /**
     * Parse and apply one CVE JSON Schema 5.1 record. Only updates a {@link Vulnerability} row
     * that already exists (see the class doc) — never creates one.
     */
    @Transactional
    RecordOutcome processRecord(byte[] data) throws IOException {
        JsonNode root = objectMapper.readTree(data);

        String cveId = root.path("cveMetadata").path("cveId").asText(null);
        if (cveId == null || cveId.isBlank()) {
            log.warn("Skipping CVE List record with no cveMetadata.cveId");
            return RecordOutcome.SKIPPED_MALFORMED;
        }

        Optional<Vulnerability> existing = vulnerabilityRepository.findById(cveId);
        if (existing.isEmpty()) {
            // CVE List knows about this CVE before NVD does — contract §12 item 2. The next NVD
            // pull creates the row; the next CVE List pull after that fills it in.
            return RecordOutcome.SKIPPED_UNKNOWN_CVE;
        }

        Vulnerability vulnerability = existing.get();

        JsonNode containers = root.path("containers");
        JsonNode cna = containers.path("cna");
        JsonNode adp = containers.path("adp");

        applyCveStatus(vulnerability, root, cna, adp);
        applyCvss(vulnerability, cna, adp);
        applySsvc(vulnerability, adp);
        applyCwe(vulnerability, cna, adp);

        vulnerabilityRepository.save(vulnerability);
        return RecordOutcome.UPDATED;
    }

    /**
     * {@code cveMetadata.state == REJECTED} wins outright; otherwise a {@code disputed} tag on the
     * CNA or any ADP container's {@code tags[]} marks it {@code DISPUTED}; otherwise
     * {@code PUBLISHED}.
     */
    private void applyCveStatus(Vulnerability vulnerability, JsonNode root, JsonNode cna, JsonNode adp) {
        String state = root.path("cveMetadata").path("state").asText("");
        if ("REJECTED".equalsIgnoreCase(state)) {
            vulnerability.setCveStatus(CveStatus.REJECTED);
            return;
        }
        if (hasDisputedTag(cna.path("tags")) || anyAdpHasDisputedTag(adp)) {
            vulnerability.setCveStatus(CveStatus.DISPUTED);
            return;
        }
        vulnerability.setCveStatus(CveStatus.PUBLISHED);
    }

    private boolean anyAdpHasDisputedTag(JsonNode adpArray) {
        if (!adpArray.isArray()) {
            return false;
        }
        for (JsonNode entry : adpArray) {
            if (hasDisputedTag(entry.path("tags"))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasDisputedTag(JsonNode tags) {
        if (!tags.isArray()) {
            return false;
        }
        for (JsonNode tag : tags) {
            String value = tag.asText("");
            if (value.toLowerCase(Locale.ROOT).contains("disputed")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Precedence NVD → CNA → ADP, only overwriting a lower-precedence value with an even-lower one
     * absent — see contract §2. NVD never sets {@code cvssSource}, so "a score is present and no
     * source is recorded" is read as NVD-owned and left untouched.
     */
    private void applyCvss(Vulnerability vulnerability, JsonNode cna, JsonNode adp) {
        boolean nvdOwned = vulnerability.getCvssSource() == null && vulnerability.getCvssScore() != 0.0;
        if (nvdOwned) {
            return;
        }

        Double cnaScore = bestCvssScore(List.of(cna.path("metrics")));
        if (cnaScore != null) {
            vulnerability.setCvssScore(cnaScore);
            vulnerability.setCvssSource("CNA");
            return;
        }

        // Nothing better than what a prior CNA pass already recorded — an ADP-only record on this
        // pull must not downgrade it.
        if ("CNA".equals(vulnerability.getCvssSource())) {
            return;
        }

        List<JsonNode> adpMetricsArrays = new ArrayList<>();
        if (adp.isArray()) {
            for (JsonNode entry : adp) {
                adpMetricsArrays.add(entry.path("metrics"));
            }
        }
        Double adpScore = bestCvssScore(adpMetricsArrays);
        if (adpScore != null) {
            vulnerability.setCvssScore(adpScore);
            vulnerability.setCvssSource("ADP");
        }
    }

    /** Highest CVSS schema version present across the given {@code metrics[]} arrays, preferring 3.1 > 3.0 > 2.0. */
    private Double bestCvssScore(List<JsonNode> metricsArrays) {
        Double bestV31 = null;
        Double bestV30 = null;
        Double bestV20 = null;

        for (JsonNode metricsArray : metricsArrays) {
            if (!metricsArray.isArray()) {
                continue;
            }
            for (JsonNode metric : metricsArray) {
                if (metric.has("cvssV3_1")) {
                    Double score = readBaseScore(metric.path("cvssV3_1"));
                    if (score != null && (bestV31 == null || score > bestV31)) {
                        bestV31 = score;
                    }
                } else if (metric.has("cvssV3_0")) {
                    Double score = readBaseScore(metric.path("cvssV3_0"));
                    if (score != null && (bestV30 == null || score > bestV30)) {
                        bestV30 = score;
                    }
                } else if (metric.has("cvssV2_0")) {
                    Double score = readBaseScore(metric.path("cvssV2_0"));
                    if (score != null && (bestV20 == null || score > bestV20)) {
                        bestV20 = score;
                    }
                }
            }
        }

        if (bestV31 != null) {
            return bestV31;
        }
        if (bestV30 != null) {
            return bestV30;
        }
        return bestV20;
    }

    private Double readBaseScore(JsonNode cvssNode) {
        JsonNode baseScore = cvssNode.path("baseScore");
        return baseScore.isMissingNode() || baseScore.isNull() ? null : baseScore.asDouble();
    }

    /**
     * Raw lowercase SSVC tokens from the ADP container's {@code ssvc} metric — see contract §2.
     * Parsed defensively against the {@code content.options[]} shape (a list of single-key objects)
     * and, as a fallback, a flat {@code content} object carrying the same keys directly, since the
     * ADP SSVC block has gone through format revisions.
     */
    private void applySsvc(Vulnerability vulnerability, JsonNode adpArray) {
        if (!adpArray.isArray()) {
            return;
        }

        String exploitation = null;
        String automatable = null;
        String technicalImpact = null;

        for (JsonNode adpEntry : adpArray) {
            for (JsonNode metric : adpEntry.path("metrics")) {
                JsonNode other = metric.path("other");
                if (!"ssvc".equalsIgnoreCase(other.path("type").asText(""))) {
                    continue;
                }
                JsonNode content = other.path("content");
                List<JsonNode> pairs = new ArrayList<>();
                JsonNode options = content.path("options");
                if (options.isArray() && !options.isEmpty()) {
                    options.forEach(pairs::add);
                } else if (content.isObject()) {
                    pairs.add(content);
                }

                for (JsonNode pair : pairs) {
                    Iterator<Map.Entry<String, JsonNode>> fields = pair.fields();
                    while (fields.hasNext()) {
                        Map.Entry<String, JsonNode> field = fields.next();
                        String key = field.getKey().toLowerCase(Locale.ROOT).replace(" ", "");
                        String value = field.getValue().asText(null);
                        if (value == null || value.isBlank()) {
                            continue;
                        }
                        value = value.trim().toLowerCase(Locale.ROOT);
                        switch (key) {
                            case "exploitation" -> exploitation = exploitation == null ? value : exploitation;
                            case "automatable" -> automatable = automatable == null ? value : automatable;
                            case "technicalimpact" -> technicalImpact = technicalImpact == null ? value : technicalImpact;
                            default -> { /* unrecognized SSVC decision point — ignore */ }
                        }
                    }
                }
            }
        }

        if (exploitation != null) {
            vulnerability.setSsvcExploitation(exploitation);
        }
        if (automatable != null) {
            vulnerability.setSsvcAutomatable(automatable);
        }
        if (technicalImpact != null) {
            vulnerability.setSsvcTechnicalImpact(technicalImpact);
        }
    }

    /** Comma-joined, deduped, truncated at 255 — every {@code problemTypes[]} entry from CNA and every ADP container. */
    private void applyCwe(Vulnerability vulnerability, JsonNode cna, JsonNode adp) {
        Set<String> cwes = new LinkedHashSet<>();
        collectCwe(cna.path("problemTypes"), cwes);
        if (adp.isArray()) {
            for (JsonNode adpEntry : adp) {
                collectCwe(adpEntry.path("problemTypes"), cwes);
            }
        }
        if (cwes.isEmpty()) {
            return;
        }
        String joined = String.join(",", cwes);
        vulnerability.setCwe(truncate(joined, 255));
    }

    private void collectCwe(JsonNode problemTypes, Set<String> out) {
        if (!problemTypes.isArray()) {
            return;
        }
        for (JsonNode problemType : problemTypes) {
            for (JsonNode description : problemType.path("descriptions")) {
                String cweId = description.path("cweId").asText(null);
                if (cweId != null && !cweId.isBlank()) {
                    out.add(cweId);
                }
            }
        }
    }

    private static String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

}
