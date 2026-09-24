package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.nvd.NVDCVEResult;
import net.jdesive.secy.persistence.NvdIngestCursorRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.NvdIngestCursor;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The regression this pins: {@link NVDService#saveVulnerabilities} re-ingesting a CVE that already
 * has a real {@link VulnerabilityAlert} against it used to throw
 * {@code HibernateException: A collection with cascade="all-delete-orphan" was no longer
 * referenced by the owning entity instance: Vulnerability.alerts} — reported against a real,
 * actively-correlating database, where every prior test happened to run against CVEs with no
 * alerts yet and so never exercised this path.
 *
 * <p>Root cause: {@code saveVulnerabilities} built a brand-new detached {@link Vulnerability} for
 * every CVE and saved it. Because {@code Vulnerability}'s {@code @Id} is manually assigned (no
 * {@code @GeneratedValue}), Spring Data's default {@code isNew()} check always routes {@code save()}
 * through {@code entityManager.merge(...)}. Merging an object whose {@code alerts} field is Java
 * {@code null} (it has no field initializer, unlike its sibling collections
 * {@code references}/{@code cpeOperators}) onto a managed entity that already has a real, tracked
 * {@code orphanRemoval=true} collection for that role is exactly what Hibernate refuses at flush
 * time. The fix loads the existing managed row first and mutates it in place, never touching
 * {@code alerts} at all.
 */
@SpringBootTest
class NVDServiceTest {

    private static final String CVE_ID = "CVE-2021-44228";

    @Autowired
    private NVDService nvdService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityAlertRepository vulnerabilityAlertRepository;

    @Autowired
    private SBOMComponentRepository sbomComponentRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private NvdIngestCursorRepository cursorRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer nvd;

    /**
     * Not {@code @Transactional} — {@code ingestData}'s windowed sweep persists the cursor with its
     * own {@code save()} call between windows, same as {@code KEVService}'s chunked writes, so a
     * wrapping test transaction would hide exactly the "does the cursor actually land in the
     * database" behaviour these tests exist to check. Clean up explicitly instead.
     */
    @BeforeEach
    void setUp() {
        cursorRepository.deleteAll();
        nvd = MockRestServiceServer.bindTo(restTemplate).build();
    }

    @AfterEach
    void tearDown() {
        cursorRepository.deleteAll();
        vulnerabilityRepository.deleteAll();
    }

    /**
     * A minimal, hand-built NVD 2.0 API response for one CVE. {@code metrics} must be present (even
     * empty) — {@code saveVulnerabilities} calls {@code getMetrics().getCvssMetricV2()} with no
     * null-check on {@code getMetrics()} itself.
     */
    private static String nvdResultJson(String lastModified) {
        return """
                {
                  "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                  "vulnerabilities": [
                    { "cve": {
                        "id": "%s",
                        "sourceIdentifier": "security@apache.org",
                        "published": "2021-12-10T10:15:09.143",
                        "lastModified": "%s",
                        "vulnStatus": "Analyzed",
                        "descriptions": [ { "lang": "en", "value": "Updated description text." } ],
                        "metrics": {}
                    } }
                  ]
                }
                """.formatted(CVE_ID, lastModified);
    }

    @Test
    @Transactional
    void reIngestingACveWithARealAlertDoesNotThrowAndLeavesTheAlertInPlace() throws Exception {
        Product product = new Product();
        product.setName("re-ingest-nvd-test-" + UUID.randomUUID());
        product.setCreatedAt(LocalDateTime.now());
        product = productRepository.save(product);

        SBOM sbom = new SBOM();
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setProduct(product);
        sbom = sbomRepository.save(sbom);

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setSbom(sbom);
        component = sbomComponentRepository.save(component);

        // The CVE, pre-existing exactly as NVD's own ingest would have originally created it.
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setId(CVE_ID);
        vulnerability.setDescription("Original description.");
        // Vulnerability's @Id is manually assigned, so save() routes through entityManager.merge(),
        // which returns a *different*, managed instance -- the local `vulnerability` reference stays
        // detached unless reassigned here. Skipping this is exactly the bug this test exists to catch.
        vulnerability = vulnerabilityRepository.save(vulnerability);

        // A real alert already correlated against it — this is the piece every earlier test ran
        // without, since it always ingested into an empty table.
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(vulnerability);
        alert.setComponent(component);
        alert = vulnerabilityAlertRepository.save(alert);
        UUID alertId = alert.getId();

        NVDCVEResult result = objectMapper.readValue(
                nvdResultJson("2023-11-07T03:39:22.140"), NVDCVEResult.class);

        assertThatCode(() -> nvdService.saveVulnerabilities(result)).doesNotThrowAnyException();

        Vulnerability reloaded = vulnerabilityRepository.findById(CVE_ID).orElseThrow();
        assertThat(reloaded.getDescription()).isEqualTo("Updated description text.");

        // The alert must still exist, still pointing at the same CVE and component -- a re-ingest
        // must never silently orphan-delete alerts it has no business touching.
        VulnerabilityAlert stillThere = vulnerabilityAlertRepository.findById(alertId).orElseThrow();
        assertThat(stillThere.getVulnerability().getId()).isEqualTo(CVE_ID);
        assertThat(stillThere.getComponent().getId()).isEqualTo(component.getId());
        assertThat(vulnerabilityAlertRepository.count()).isEqualTo(1);
    }

    @Test
    @Transactional
    void savingABrandNewCveStillWorks() throws Exception {
        NVDCVEResult result = objectMapper.readValue(
                nvdResultJson("2023-11-07T03:39:22.140"), NVDCVEResult.class);

        int written = nvdService.saveVulnerabilities(result);

        assertThat(written).isEqualTo(1);
        assertThat(vulnerabilityRepository.findById(CVE_ID)).isPresent();
    }

    /* ------------------------------------------------------------------ */
    /* Windowed incremental ingest — the fix for "restart from CVE #1"    */
    /* ------------------------------------------------------------------ */

    private static final String WINDOW_CVE_ID = "CVE-2024-9001";

    private static String nvdWindowResultJson() {
        return """
                {
                  "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                  "vulnerabilities": [
                    { "cve": {
                        "id": "%s",
                        "sourceIdentifier": "security@apache.org",
                        "published": "2024-01-10T10:15:09.143",
                        "lastModified": "2024-01-10T10:15:09.143",
                        "vulnStatus": "Analyzed",
                        "descriptions": [ { "lang": "en", "value": "A window-fetched CVE." } ],
                        "metrics": {}
                    } }
                  ]
                }
                """.formatted(WINDOW_CVE_ID);
    }

    /**
     * A cursor a few days old needs exactly one window to reach "now" — deliberately not testing a
     * from-scratch sweep (no cursor row at all), which would need on the order of 80 mocked requests
     * to walk from 1999 to today in 119-day steps. That sweep is the same code path run repeatedly;
     * this pins the code path itself.
     */
    @Test
    void ingestDataWithARecentCursorSweepsOneWindowAndAdvancesThePastIt() {
        NvdIngestCursor cursor = new NvdIngestCursor();
        cursor.setId("nvd");
        cursor.setLastModified(LocalDateTime.now().minusDays(3));
        cursorRepository.save(cursor);

        nvd.expect(requestTo(startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(queryParam("startIndex", "0"))
                .andRespond(withSuccess(nvdWindowResultJson(), MediaType.APPLICATION_JSON));

        IngestResult result = nvdService.ingestData(JobProgress.NOOP);

        nvd.verify();
        assertThat(result.itemsProcessed()).isEqualTo(1);
        assertThat(vulnerabilityRepository.findById(WINDOW_CVE_ID)).isPresent();

        NvdIngestCursor updated = cursorRepository.findById("nvd").orElseThrow();
        assertThat(updated.getLastModified()).isAfter(LocalDateTime.now().minusMinutes(1));
        assertThat(updated.getLastIngestedAt()).isNotNull();
    }

    /**
     * A brand-new install has no cursor row at all, so the sweep starts from the fixed 1999 epoch —
     * roughly 80-something windows to reach "now" from there, not one, so this cancels after the
     * first window completes (the same technique as the cancellation test below) rather than mocking
     * the whole sweep: the point here is only that a from-scratch sweep starts at the epoch, not that
     * it can run to completion in a test.
     */
    @Test
    void ingestDataWithNoCursorStartsSweepingFromTheFixedEpoch() {
        assertThat(cursorRepository.findById("nvd")).isEmpty();

        nvd.expect(requestTo(startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(nvdWindowResultJson(), MediaType.APPLICATION_JSON));

        AtomicBoolean firstWindowReported = new AtomicBoolean(false);
        JobProgress cancelAfterFirstWindow = new JobProgress() {
            @Override
            public void report(int itemsProcessed, String message) {
                firstWindowReported.set(true);
            }

            @Override
            public boolean isCancelled() {
                return firstWindowReported.get();
            }
        };

        assertThatThrownBy(() -> nvdService.ingestData(cancelAfterFirstWindow))
                .isInstanceOf(CancellationException.class);

        nvd.verify();
        NvdIngestCursor created = cursorRepository.findById("nvd").orElseThrow();
        assertThat(created.getLastModified()).isEqualTo(LocalDateTime.of(1999, 1, 1, 0, 0).plusDays(119));
    }

    /**
     * The regression this pins: before the windowed sweep, an ingest interrupted partway restarted
     * from CVE #1 on the next attempt — with NVD returning undated results in roughly ascending-id
     * order, a feed that never finished a run never reached anything from the last decade. Cancelling
     * between windows must leave the cursor at the end of the last window that actually completed,
     * not roll back past it and not skip ahead — the only assertion {@code MockRestServiceServer}
     * having exactly one expectation registered doesn't already make: a second HTTP call (starting
     * the next window anyway) would fail the test on its own.
     */
    @Test
    void cancellationBetweenWindowsLeavesTheCursorAtTheLastCompletedWindow() {
        LocalDateTime start = LocalDateTime.now().minusDays(150);
        NvdIngestCursor cursor = new NvdIngestCursor();
        cursor.setId("nvd");
        cursor.setLastModified(start);
        cursorRepository.save(cursor);

        nvd.expect(requestTo(startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(nvdWindowResultJson(), MediaType.APPLICATION_JSON));

        AtomicBoolean firstWindowReported = new AtomicBoolean(false);
        JobProgress cancelAfterFirstWindow = new JobProgress() {
            @Override
            public void report(int itemsProcessed, String message) {
                firstWindowReported.set(true);
            }

            @Override
            public boolean isCancelled() {
                return firstWindowReported.get();
            }
        };

        assertThatThrownBy(() -> nvdService.ingestData(cancelAfterFirstWindow))
                .isInstanceOf(CancellationException.class);

        nvd.verify();
        NvdIngestCursor updated = cursorRepository.findById("nvd").orElseThrow();
        // Truncated to millis on both sides: H2's TIMESTAMP column preserves microsecond precision,
        // not the nanosecond precision LocalDateTime.now() (start's source) actually carries, so an
        // exact isEqualTo here is comparing precision the database never round-trips.
        assertThat(updated.getLastModified().truncatedTo(java.time.temporal.ChronoUnit.MILLIS))
                .isEqualTo(start.plusDays(119).truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
    }

}
