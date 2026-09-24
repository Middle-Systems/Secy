package net.jdesive.secy.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.entity.CPEMatch;
import net.jdesive.secy.persistence.entity.CPEOperator;
import net.jdesive.secy.persistence.entity.NvdIngestCursor;
import net.jdesive.secy.persistence.entity.Reference;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.nvd.*;
import net.jdesive.secy.persistence.NvdIngestCursorRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;

@Slf4j
@Service
public class NVDService {

    /** The one {@link NvdIngestCursor} row. */
    private static final String CURSOR_ID = "nvd";

    /**
     * NVD's own cap on {@code lastModEndDate - lastModStartDate}, minus a one-day safety margin —
     * see {@link #ingestData(JobProgress)}.
     */
    private static final int WINDOW_DAYS = 119;

    /**
     * Where a from-scratch sweep starts when no {@link NvdIngestCursor} row exists yet. CVE ids
     * predate this (there are {@code CVE-1999-*} entries), but nothing meaningfully affecting
     * software still in use does, and starting here keeps the very first sweep to a bounded, known
     * number of windows rather than guessing at NVD's true earliest record.
     */
    private static final LocalDateTime EPOCH = LocalDateTime.of(1999, 1, 1, 0, 0);

    private static final DateTimeFormatter NVD_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

    private VulnerabilityRepository vulnerabilityRepository;

    private final NvdIngestCursorRepository cursorRepository;

    private final RestTemplate restTemplate;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * A self-reference through the Spring proxy, {@code @Lazy} to sidestep the circular-bean-creation
     * this would otherwise be. {@link #ingestWindow} calls {@link #saveVulnerabilities} through this
     * rather than directly — a direct {@code this.saveVulnerabilities(...)} call from another method
     * on the same bean bypasses the proxy {@code @Transactional} relies on entirely, so
     * {@code saveVulnerabilities}'s own transaction would silently never start and its
     * {@code entityManager.persist(...)} calls would throw {@code TransactionRequiredException}. The
     * method still needs {@code @Transactional} for its own sake, since it is also called directly
     * (through the proxy, correctly) by anything ingesting a single already-fetched page, including
     * {@code NVDServiceTest}.
     */
    @Autowired
    @Lazy
    private NVDService self;

    @Autowired
    public NVDService(VulnerabilityRepository vulnerabilityRepository,
                       NvdIngestCursorRepository cursorRepository, RestTemplate restTemplate) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.cursorRepository = cursorRepository;
        this.restTemplate = restTemplate;
    }

    private final String cveApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private final int resultsPerPage = 2000;

    @Value("${nvd.apikey}")
    private String apiKey;

    public Vulnerability getVulnerabilityById(String id) {
        Optional<Vulnerability> optional = this.vulnerabilityRepository.findById(id);

        if (!optional.isPresent()) {
            throw new RuntimeException("Vulnerability with id [" + id + "] was not found");
        }

        return optional.get();
    }

    public Page<Vulnerability> findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(String search, int page, int size) {
        return vulnerabilityRepository.findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                search, search, PageRequest.of(page, size));
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingestData() {
        return ingestData(JobProgress.NOOP);
    }

    /**
     * Sweep NVD for CVEs modified since the last successful ingest, reporting the running count to
     * {@code progress} after each page.
     *
     * <p>NVD's CVE API accepts {@code lastModStartDate}/{@code lastModEndDate} to pull only records
     * modified in a window, capped at 120 days per request. This walks from {@link NvdIngestCursor}
     * (or {@link #EPOCH}, on the very first ever ingest — there is no cursor yet, so there is
     * nothing narrower to ask NVD for) to now in {@value #WINDOW_DAYS}-day windows, one full paged
     * crawl of {@code resultsPerPage} each per window.
     *
     * <p>The cursor is persisted after <b>each window completes</b>, not just once at the end of the
     * whole sweep. That is the entire point: a run interrupted partway — by a redeploy, a crash,
     * anything — only has to redo the window it was on when it stopped, not the whole feed. Before
     * this, every interrupted ingest restarted from CVE #1, and since NVD returns undated results in
     * roughly ascending-CVE-id order, a run that never reaches the end never ingests anything from
     * roughly the last decade — which is why every product's actionable list could come back empty
     * even with an ingest that "completed" several times.
     *
     * @throws CancellationException if {@code progress} asks to stop between pages or windows
     */
    public IngestResult ingestData(JobProgress progress) {
        NvdIngestCursor cursor = cursorRepository.findById(CURSOR_ID).orElse(null);
        LocalDateTime windowStart = (cursor != null && cursor.getLastModified() != null)
                ? cursor.getLastModified() : EPOCH;
        LocalDateTime now = LocalDateTime.now();

        int totalProcessed = 0;
        while (windowStart.isBefore(now)) {
            if (progress.isCancelled()) {
                throw new CancellationException("NVD ingest cancelled after " + totalProcessed + " records");
            }

            LocalDateTime windowEnd = windowStart.plusDays(WINDOW_DAYS);
            if (windowEnd.isAfter(now)) {
                windowEnd = now;
            }

            totalProcessed += ingestWindow(windowStart, windowEnd, progress, totalProcessed);
            advanceCursor(windowEnd);
            windowStart = windowEnd;
        }

        return IngestResult.of(totalProcessed, "CVE records");
    }

    /** One {@code lastModStartDate}/{@code lastModEndDate} window, fully paged. */
    private int ingestWindow(LocalDateTime windowStart, LocalDateTime windowEnd, JobProgress progress,
                              int alreadyProcessed) {
        NVDCVEResult result = this.getDataAtOffset(0, windowStart, windowEnd);
        int processed = self.saveVulnerabilities(result);
        int total = result.getTotalResults();
        int offset = this.resultsPerPage;
        progress.report(alreadyProcessed + processed,
                "Ingested " + (alreadyProcessed + processed) + " CVE records…");

        while (offset < total) {
            if (progress.isCancelled()) {
                throw new CancellationException(
                        "NVD ingest cancelled after " + (alreadyProcessed + processed) + " records");
            }

            NVDCVEResult nestedResult = this.getDataAtOffset(offset, windowStart, windowEnd);
            offset = this.resultsPerPage + offset;
            processed += self.saveVulnerabilities(nestedResult);
            progress.report(alreadyProcessed + processed,
                    "Ingested " + (alreadyProcessed + processed) + " CVE records…");
        }

        return processed;
    }

    private void advanceCursor(LocalDateTime windowEnd) {
        NvdIngestCursor cursor = cursorRepository.findById(CURSOR_ID).orElseGet(() -> {
            NvdIngestCursor fresh = new NvdIngestCursor();
            fresh.setId(CURSOR_ID);
            return fresh;
        });
        cursor.setLastModified(windowEnd);
        cursor.setLastIngestedAt(LocalDateTime.now());
        cursorRepository.save(cursor);
    }

    /**
     * @return how many vulnerabilities were written
     *
     * <p>Writes a genuinely new CVE with {@link EntityManager#persist} rather than
     * {@code vulnerabilityRepository.save(...)}. {@code Vulnerability}'s {@code @Id} is manually
     * assigned (a CVE id, not {@code @GeneratedValue}), so Spring Data's default "is this new?"
     * check always answers no — {@code save()} on an object with a non-null id it has never seen
     * routes through {@code entityManager.merge(...)}, which for an <em>unmanaged</em> instance
     * first runs a {@code SELECT} to find out whether a row with that id already exists before it
     * can decide {@code INSERT} vs {@code UPDATE}. On a feed where most of every ingest is brand-new
     * CVEs, that is one wasted round trip per row. {@code persist()} skips it: we already know it is
     * new (nothing in {@code existing}, loaded just above), so tell Hibernate directly and let it
     * batch a plain {@code INSERT} (see {@code hibernate.jdbc.batch_size} in
     * {@code application.properties}).
     *
     * <p>A CVE already in {@code existing} needs no save call at all — {@code findAllById} loaded it
     * into this (transactional) persistence context, so it is already the exact managed instance
     * Hibernate is tracking, and the field mutations below are picked up by ordinary dirty checking
     * at flush/commit. This is also why {@code alerts} is safe to leave completely untouched:
     * mutating a managed instance in place never risks the {@code cascade=all-delete-orphan}
     * collection-replacement problem a {@code merge()} of a detached object with a null
     * {@code alerts} field used to hit (see {@code NVDServiceTest} for that regression).
     * {@code references}/{@code cpeOperators} are still cleared and rebuilt <em>in place</em> below,
     * for the same reason: NVD is the source of truth for both on every ingest, and replacing the
     * field with a new {@code ArrayList} rather than clearing the existing one risks the identical
     * disconnect the moment either ever needs an {@code orphanRemoval} child of its own.
     */
    @Transactional
    public int saveVulnerabilities(NVDCVEResult result) {

        List<String> ids = result.getVulnerabilities().stream()
                .map(v -> v.getCve().getId())
                .toList();
        Map<String, Vulnerability> existing = new HashMap<>();
        for (Vulnerability v : this.vulnerabilityRepository.findAllById(ids)) {
            existing.put(v.getId(), v);
        }

        int written = 0;
        for (NVDVulnerability nvdVulnerability : result.getVulnerabilities()) {

            String cveId = nvdVulnerability.getCve().getId();
            boolean isNew = !existing.containsKey(cveId);

            Optional<NVDCVEDescription> descriptionOptional = nvdVulnerability.getCve().getDescriptions().stream().filter(desc -> Objects.equals(desc.getLang(), "en")).findFirst();
            String description = "N/A";

            if (descriptionOptional.isPresent()) {
                description = descriptionOptional.get().getValue();
            }

            Vulnerability vulnerability = existing.getOrDefault(cveId, new Vulnerability());
            vulnerability.setId(cveId);
            // references/cpeOperators are fully re-derived from NVD on every ingest -- clear the
            // managed collection in place (not a field replacement) so a re-ingest of an existing
            // CVE correctly drops stale entries via orphanRemoval instead of accumulating duplicates.
            vulnerability.getReferences().clear();
            vulnerability.getCpeOperators().clear();
            vulnerability.setPublished(LocalDateTime.ofInstant(nvdVulnerability.getCve().getPublished().toInstant(), ZoneId.systemDefault()));
            vulnerability.setLastModified(LocalDateTime.ofInstant(nvdVulnerability.getCve().getLastModified().toInstant(), ZoneId.systemDefault()));
            vulnerability.setSourceIdentifier(nvdVulnerability.getCve().getSourceIdentifier());
            vulnerability.setDescription(description);
            vulnerability.setVulnStatus(nvdVulnerability.getCve().getVulnStatus());

            if (nvdVulnerability.getCve().getCveTags() != null) {
                StringBuilder cveTags = new StringBuilder();
                for (NVDCVETag nvdCveTag : nvdVulnerability.getCve().getCveTags()) {
                    cveTags.append(String.join(",", nvdCveTag.getTags()));
                }
                vulnerability.setCveTags(cveTags.toString());
            }

            if (nvdVulnerability.getCve().getReferences() != null) {
                for (NVDCVEReference nvdReference : nvdVulnerability.getCve().getReferences()) {
                    Reference reference = new Reference();
                    reference.setUrl(nvdReference.getUrl());
                    reference.setSource(nvdReference.getSource());
                    if (nvdReference.getTags() != null)
                        reference.setTags(String.join(",", nvdReference.getTags()));
                    reference.setCve(vulnerability);
                    vulnerability.getReferences().add(reference);
                }
            }

            if (nvdVulnerability.getCve().getWeaknesses() != null) {
                List<String> tags = new ArrayList<>();
                for (NVDCVEWeakness nvdcveWeakness : nvdVulnerability.getCve().getWeaknesses()) {
                    for (NVDCVEWeaknessDescription nvdcveWeaknessDescription : nvdcveWeakness.getDescription()) {
                        tags.add(nvdcveWeaknessDescription.getValue());
                    }
                }
                vulnerability.setCwe(String.join(",", tags));
            }

            // Grab the first metric TODO: Search for primary and ingest that
            if (nvdVulnerability.getCve().getMetrics().getCvssMetricV2() != null) {
                CVSSMetricV2 metrics = nvdVulnerability.getCve().getMetrics().getCvssMetricV2().get(0);
                vulnerability.setBaseSeverity(metrics.getBaseSeverity());
                vulnerability.setAccessVector(metrics.getCvssData().getAccessVector());
                vulnerability.setAccessComplexity(metrics.getCvssData().getAccessComplexity());
                vulnerability.setAuthenticationRequired(metrics.getCvssData().getAuthentication());
                vulnerability.setConfidentialityImpact(metrics.getCvssData().getConfidentialityImpact());
                vulnerability.setIntegrityImpact(metrics.getCvssData().getIntegrityImpact());
                vulnerability.setAvailabilityImpact(metrics.getCvssData().getAvailabilityImpact());
                vulnerability.setCvssScore(metrics.getCvssData().getBaseScore());
                vulnerability.setExploitabilityScore(metrics.getExploitabilityScore());
                vulnerability.setImpactScore(metrics.getImpactScore());
                vulnerability.setCanObtainAllPrivilege(metrics.isObtainAllPrivilege());
                vulnerability.setCanObtainUserPrivilege(metrics.isObtainUserPrivilege());
                vulnerability.setCanObtainOtherPrivilege(metrics.isObtainOtherPrivilege());
                vulnerability.setUserInteractionRequired(metrics.isUserInteractionRequired());
            }

            if (nvdVulnerability.getCve().getConfigurations() != null) {
                for (NVDCVEConfiguration nvdConfiguration : nvdVulnerability.getCve().getConfigurations()) {
                    for (NVDCVEConfigurationNode nvdNode : nvdConfiguration.getNodes()) {
                        CPEOperator cpeOperator = new CPEOperator();
                        cpeOperator.setOperator(nvdNode.getOperator());
                        cpeOperator.setNegate(nvdNode.isNegate());
                        cpeOperator.setCve(vulnerability);

                        for (NVDCVEConfigurationNodeCPEMatch nvdCpeMatch : nvdNode.getCpeMatch()) {
                            CPEMatch cpeMatch = new CPEMatch();
                            cpeMatch.setVulnerable(nvdCpeMatch.isVulnerable());
                            cpeMatch.setCriteria(nvdCpeMatch.getCriteria());
                            cpeMatch.setMatchCriteriaId(nvdCpeMatch.getMatchCriteriaId());
                            // The affected range. Without these four the criteria string's version
                            // field is a bare wildcard and correlation cannot tell an affected
                            // version from a patched one — see CPEMatch.versionStartIncluding.
                            cpeMatch.setVersionStartIncluding(nvdCpeMatch.getVersionStartIncluding());
                            cpeMatch.setVersionStartExcluding(nvdCpeMatch.getVersionStartExcluding());
                            cpeMatch.setVersionEndIncluding(nvdCpeMatch.getVersionEndIncluding());
                            cpeMatch.setVersionEndExcluding(nvdCpeMatch.getVersionEndExcluding());
                            cpeMatch.setOperator(cpeOperator);

                            cpeOperator.getCpeMatches().add(cpeMatch);
                        }
                        vulnerability.getCpeOperators().add(cpeOperator);
                    }
                }
            }

            if (isNew) {
                entityManager.persist(vulnerability);
            }
            log.debug("Saving vuln {}", vulnerability);
            written++;
        }
        return written;
    }

    private NVDCVEResult getDataAtOffset(int offset, LocalDateTime windowStart, LocalDateTime windowEnd) {

        log.debug("Fetching NVD Vulnerability data from offset {} for window [{}, {}]", offset, windowStart, windowEnd);

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + this.apiKey);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        String urlTemplate = UriComponentsBuilder.fromHttpUrl(this.cveApiUrl)
                .queryParam("resultsPerPage", this.resultsPerPage)
                .queryParam("startIndex", offset)
                .queryParam("lastModStartDate", formatForNvd(windowStart))
                .queryParam("lastModEndDate", formatForNvd(windowEnd))
                .encode()
                .toUriString();

        ResponseEntity<NVDCVEResult> result = this.restTemplate.exchange(urlTemplate, HttpMethod.GET, entity, NVDCVEResult.class);

        if (!result.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Error processing NVD Data. API returned non success status code. [" + result.getStatusCode().value() + "]");
        }

        return result.getBody();
    }

    /** NVD requires an explicit UTC offset on {@code lastModStartDate}/{@code lastModEndDate}. */
    private static String formatForNvd(LocalDateTime dateTime) {
        return ZonedDateTime.of(dateTime, ZoneId.systemDefault()).format(NVD_DATE_FORMAT);
    }

}
