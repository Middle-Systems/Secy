package net.jdesive.secy.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the app for real and checks springdoc is wired up: the spec is served at the pinned
 * path, carries our {@link OpenApiConfig} metadata, and lists the controllers' endpoints.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpenApiDocsTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void apiDocsAreServedAndDescribeTheKnownEndpoints() {
        ResponseEntity<String> response = restTemplate.getForEntity("/v3/api-docs", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        String body = response.getBody();
        assertThat(body).isNotNull();

        assertThat(body)
                .as("info block from OpenApiConfig")
                .contains("\"title\":\"Secy API\"")
                .contains("\"name\":\"AGPL-3.0\"")
                .contains("https://www.gnu.org/licenses/agpl-3.0.html");

        assertThat(body)
                .as("one path per controller")
                .contains("\"/kev\"")
                .contains("\"/kev/ingest\"")
                .contains("\"/epss\"")
                .contains("\"/nvd/search\"")
                .contains("\"/nvd/id/{cveId}\"")
                .contains("\"/products\"")
                .contains("\"/products/{productId}/owners\"")
                .contains("\"/sbom/{sbomId}/vulnerabilities\"")
                .contains("\"/stats/dashboard\"")
                .contains("\"/compliance/reports\"")
                .contains("\"/compliance/reports/{id}/scan\"")
                // Phase 6.
                .contains("\"/compromise\"")
                .contains("\"/compromise/{id}\"")
                .contains("\"/threat/ingest\"")
                .contains("\"/threat/ingest/malicious-packages\"")
                .contains("\"/threat/ingest/malware-hashes\"")
                .contains("\"/threat/malicious-packages\"")
                .contains("\"/threat/malware-hashes\"")
                // M1e.
                .contains("\"/lifecycle-drift\"")
                .contains("\"/lifecycle-drift/{id}\"")
                // M1f.
                .contains("\"/vex\"")
                .contains("\"/vex/documents\"")
                .contains("\"/vex/documents/{id}\"")
                .contains("\"/vex/documents/{id}/statements\"")
                .contains("\"/vex/documents/{id}/deactivate\"")
                .contains("\"/vex/statements\"")
                .contains("\"/vex/reconcile\"")
                .contains("\"/vex/settings/precedence\"")
                // M1g.
                .contains("\"/cbom/assets\"")
                .contains("\"/cbom/assets/{id}\"")
                .contains("\"/cbom/quantum-findings\"")
                .contains("\"/cbom/quantum-findings/{id}\"")
                // M1h.
                .contains("\"/sbom-quality\"")
                .contains("\"/sbom-quality/{id}\"")
                // M1i.
                .contains("\"/products/{id}/risk-score\"")
                .contains("\"/assets/{id}/risk-score\"")
                .contains("\"/risk-score/model\"")
                .contains("\"/risk-score/rescore\"");

        assertThat(body)
                .as("@Tag names")
                .contains("\"KEV\"")
                .contains("\"EPSS\"")
                .contains("\"NVD\"")
                .contains("\"Products\"")
                .contains("\"Ownership\"")
                .contains("\"SBOM\"")
                .contains("\"Stats\"")
                .contains("\"Compliance\"")
                .contains("\"Compromise\"")
                .contains("\"Threat\"")
                .contains("\"Lifecycle drift\"")
                .contains("\"VEX\"")
                .contains("\"CBOM\"")
                .contains("\"SBOM quality\"")
                .contains("\"Risk score\"");

        assertThat(body)
                .as("the GET /actionable typed union is described to clients — itemType is the "
                        + "discriminator a UI switches on, and the compromise arm's fields have to be "
                        + "in the schema for a generated client to see them")
                .contains("\"itemType\"")
                .contains("\"compromiseType\"")
                .contains("\"compromiseConfidence\"")
                .contains("\"iocId\"")
                .contains("\"matchedOn\"");
    }

    @Test
    void swaggerUiIsServedAtTheDefaultPath() {
        ResponseEntity<String> response = restTemplate.getForEntity("/swagger-ui.html", String.class);

        // springdoc redirects /swagger-ui.html to the bundled index page.
        assertThat(response.getStatusCode())
                .isIn(HttpStatus.OK, HttpStatus.FOUND, HttpStatus.MOVED_PERMANENTLY);
    }
}
