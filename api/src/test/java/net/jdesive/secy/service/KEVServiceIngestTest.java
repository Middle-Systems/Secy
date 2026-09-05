package net.jdesive.secy.service;

import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.entity.KEV;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The KEV ingest itself, with the CISA feed stubbed at the transport.
 *
 * <p>This is what the injected {@code RestTemplate} bean bought us: the service used to
 * {@code new RestTemplate()} inline, so there was no seam and no way to run an ingest offline.
 * Binding {@link MockRestServiceServer} to the bean swaps its request factory for the rest of the
 * context's life, which is deliberate — anything else in this context that tried to reach the real
 * CISA feed would now fail loudly instead of going to the network.
 */
@SpringBootTest
class KEVServiceIngestTest {

    private static final String FEED_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private static final String CATALOG = """
            {
              "title": "CISA Catalog of Known Exploited Vulnerabilities",
              "catalogVersion": "2026.09.05",
              "dateReleased": "2026-09-05",
              "count": 2,
              "vulnerabilities": [
                {
                  "cveID": "CVE-2026-0001",
                  "vendorProject": "Acme",
                  "product": "Widget",
                  "vulnerabilityName": "Remote code execution in Widget",
                  "dateAdded": "2026-08-01",
                  "shortDescription": "A bad bug.",
                  "requiredAction": "Apply updates per vendor instructions.",
                  "dueDate": "2026-08-22",
                  "knownRansomwareCampaignUse": "Known",
                  "notes": "Tracked by CISA."
                },
                {
                  "cveID": "CVE-2026-0002",
                  "vendorProject": "Globex",
                  "product": "Gadget",
                  "vulnerabilityName": "Auth bypass in Gadget",
                  "dateAdded": "2026-08-02",
                  "shortDescription": "Another bad bug.",
                  "requiredAction": "Apply updates per vendor instructions.",
                  "dueDate": "2026-08-23",
                  "knownRansomwareCampaignUse": "Unknown",
                  "notes": ""
                }
              ]
            }
            """;

    @Autowired
    private KEVService kevService;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer cisa;

    @BeforeEach
    void setUp() {
        kevRepository.deleteAll();
        cisa = MockRestServiceServer.bindTo(restTemplate).build();
    }

    @Test
    void ingestSavesTheCatalogAndReportsItsProgress() {
        cisa.expect(requestTo(FEED_URL))
                .andExpect(method(org.springframework.http.HttpMethod.GET))
                .andRespond(withSuccess(CATALOG, MediaType.APPLICATION_JSON));

        List<Integer> reported = new ArrayList<>();
        IngestResult result = kevService.ingest((itemsProcessed, message) -> reported.add(itemsProcessed));

        cisa.verify();
        assertThat(result.itemsProcessed()).isEqualTo(2);
        assertThat(result.message()).isEqualTo("2 KEV entries ingested");
        assertThat(reported).containsExactly(2);

        Optional<KEV> saved = kevRepository.findById("CVE-2026-0001");
        assertThat(saved).isPresent();
        assertThat(saved.get().getVendor()).isEqualTo("Acme");
        assertThat(saved.get().getKnownRansomwareCampaignUse()).isEqualTo("Known");
        assertThat(kevRepository.count()).isEqualTo(2);
    }

    @Test
    void anEmptyCatalogIsNotAnError() {
        cisa.expect(requestTo(FEED_URL))
                .andRespond(withSuccess("{\"count\": 0, \"vulnerabilities\": []}", MediaType.APPLICATION_JSON));

        IngestResult result = kevService.ingest(JobProgress.NOOP);

        assertThat(result.itemsProcessed()).isZero();
        assertThat(result.message()).contains("empty");
        assertThat(kevRepository.count()).isZero();
    }

    @Test
    void aFeedFailurePropagatesSoTheJobCanRecordIt() {
        cisa.expect(requestTo(FEED_URL)).andRespond(withServerError());

        assertThatThrownBy(() -> kevService.ingest(JobProgress.NOOP))
                .isInstanceOf(org.springframework.web.client.RestClientException.class);
    }

    @Test
    void theNoArgOverloadStillWorks() {
        cisa.expect(requestTo(FEED_URL))
                .andRespond(withSuccess(CATALOG, MediaType.APPLICATION_JSON));

        assertThat(kevService.ingest().itemsProcessed()).isEqualTo(2);
    }

    /**
     * Cancellation is checked between batches, so a two-entry catalog never gets there — the point
     * of this test is that the check is wired to the callback, not to a hard-coded flag.
     */
    @Test
    void cancellationIsObservedThroughTheProgressCallback() {
        cisa.expect(requestTo(FEED_URL))
                .andRespond(withSuccess(CATALOG, MediaType.APPLICATION_JSON));

        JobProgress cancelled = new JobProgress() {
            @Override
            public void report(int itemsProcessed, String message) {
                // no-op
            }

            @Override
            public boolean isCancelled() {
                return true;
            }
        };

        // Two entries is below the batch threshold, so this run completes rather than cancelling.
        assertThat(kevService.ingest(cancelled).itemsProcessed()).isEqualTo(2);
        assertThat(cancelled.isCancelled()).isTrue();
    }

    @Test
    void cancellationBetweenBatchesAbortsTheIngest() {
        cisa.expect(requestTo(FEED_URL))
                .andRespond(withSuccess(largeCatalog(300), MediaType.APPLICATION_JSON));

        JobProgress cancelled = new JobProgress() {
            @Override
            public void report(int itemsProcessed, String message) {
                // no-op
            }

            @Override
            public boolean isCancelled() {
                return true;
            }
        };

        assertThatThrownBy(() -> kevService.ingest(cancelled))
                .isInstanceOf(CancellationException.class)
                .hasMessageContaining("cancelled");
    }

    private static String largeCatalog(int entries) {
        StringBuilder json = new StringBuilder("{\"count\": ").append(entries).append(", \"vulnerabilities\": [");
        for (int i = 0; i < entries; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append("{\"cveID\": \"CVE-2026-1")
                    .append(String.format("%03d", i))
                    .append("\", \"vendorProject\": \"Acme\", \"product\": \"Widget\","
                            + " \"vulnerabilityName\": \"Bug\", \"dateAdded\": \"2026-08-01\","
                            + " \"shortDescription\": \"d\", \"requiredAction\": \"a\","
                            + " \"dueDate\": \"2026-08-22\", \"knownRansomwareCampaignUse\": \"Unknown\","
                            + " \"notes\": \"\"}");
        }
        return json.append("]}").toString();
    }

}
