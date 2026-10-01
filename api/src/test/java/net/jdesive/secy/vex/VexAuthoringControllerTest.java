package net.jdesive.secy.vex;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.ProductService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M1k's T6 — see ROADMAP.md's M1k section 10. Modeled on {@code VexAcceptanceTest}'s
 * upload/poll/await-terminal pattern; deliberately NOT {@code @Transactional}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class VexAuthoringControllerTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ProductService productService;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    private UUID productId;

    @Autowired
    private net.jdesive.secy.persistence.AppUserRepository userRepository;

    @BeforeEach
    void seed() {
        alertRepository.deleteAll();
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        userRepository.deleteAll();

        Product product = new Product();
        product.setName("T6 Product " + UUID.randomUUID());
        productId = productRepository.save(product).getId();
    }

    @AfterEach
    void cleanup() {
        alertRepository.deleteAll();
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        // Also after the LAST test in this class, so no account leaks into a later test class that
        // relies on M0's "first registered account becomes ADMIN" bootstrap rule.
        userRepository.deleteAll();
    }

    @Test
    void validAuthoredStatementQueuesAndShowsUpOnStatementsBrowse() throws Exception {
        String token = registerAndLogin("t6-engineer@example.com");
        long jobsBefore = jobRepository.count();

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8001",
                "productId", productId.toString(),
                "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "status", "NOT_AFFECTED",
                "justification", "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH"));

        MvcResult result = mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isAccepted())
                .andReturn();

        assertThat(jobRepository.count()).isEqualTo(jobsBefore + 1);
        UUID jobId = extractJobId(result.getResponse().getContentAsString());
        jobRunner.poll();
        awaitJobTerminal(jobId);

        mockMvc.perform(get("/vex/statements").param("cveId", "CVE-2099-8001")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].author").value("t6-engineer@example.com"))
                .andExpect(jsonPath("$.content[0].format").value("OPENVEX"));
    }

    @Test
    void reasonlessNotAffectedIs400AndQueuesNothing() throws Exception {
        String token = registerAndLogin("t6-reasonless@example.com");
        long jobsBefore = jobRepository.count();

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8002", "productId", productId.toString(),
                "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "status", "NOT_AFFECTED"));

        mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void nonCveIdIs400() throws Exception {
        String token = registerAndLogin("t6-badcve@example.com");
        long jobsBefore = jobRepository.count();

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "NOT-A-CVE", "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "status", "AFFECTED"));

        mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void unusablePurlIs400() throws Exception {
        String token = registerAndLogin("t6-badpurl@example.com");
        long jobsBefore = jobRepository.count();

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8003", "purl", "", "status", "AFFECTED"));

        mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void unassignedProductIs400() throws Exception {
        String token = registerAndLogin("t6-unassigned@example.com");
        Product unassigned = productService.getOrCreateUnassigned(Tenant.DEFAULT_TENANT_ID);
        long jobsBefore = jobRepository.count();

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8004", "productId", unassigned.getId().toString(),
                "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "status", "AFFECTED"));

        mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void unknownProductIs404() throws Exception {
        String token = registerAndLogin("t6-unknownproduct@example.com");

        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8005", "productId", UUID.randomUUID().toString(),
                "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "status", "AFFECTED"));

        mockMvc.perform(post("/vex/statements")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .content(body))
                .andExpect(status().isNotFound());
    }

    @Test
    void noAuthenticationIs401() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "cveId", "CVE-2099-8006", "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "status", "AFFECTED"));

        mockMvc.perform(post("/vex/statements").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void secondStatementFromSameAuthorSupersedesTheFirstOnTheSameTarget() throws Exception {
        String token = registerAndLogin("t6-supersede@example.com");
        String purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
        String cveId = "CVE-2099-8007";
        UUID alertId = seedAlert(purl, cveId);

        authorAndAwait(token, cveId, purl, "NOT_AFFECTED", "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH", null);
        authorAndAwait(token, cveId, purl, "NOT_AFFECTED", "COMPONENT_NOT_PRESENT", null);

        mockMvc.perform(get("/actionable/{id}", alertId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vex.statements", org.hamcrest.Matchers.hasSize(2)))
                .andExpect(jsonPath("$.vex.statements[?(@.role == 'SUPERSEDED')]", org.hamcrest.Matchers.hasSize(1)))
                .andExpect(jsonPath("$.vex.statements[?(@.role == 'WON')]", org.hamcrest.Matchers.hasSize(1)));
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private void authorAndAwait(String token, String cveId, String purl, String status, String justification,
                                 String impactStatement) throws Exception {
        java.util.Map<String, Object> bodyMap = new java.util.HashMap<>();
        bodyMap.put("cveId", cveId);
        bodyMap.put("purl", purl);
        bodyMap.put("status", status);
        if (justification != null) {
            bodyMap.put("justification", justification);
        }
        if (impactStatement != null) {
            bodyMap.put("impactStatement", impactStatement);
        }
        MvcResult result = mockMvc.perform(post("/vex/statements")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyMap)))
                .andExpect(status().isAccepted())
                .andReturn();
        UUID jobId = extractJobId(result.getResponse().getContentAsString());
        jobRunner.poll();
        awaitJobTerminal(jobId);
    }

    private UUID seedAlert(String purl, String cveId) {
        Product product = productRepository.findById(productId).orElseThrow();

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl(purl);
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);

        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded by VexAuthoringControllerTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.EPSS_HIGH);
        alert.setEpssScore(0.5);
        return alertRepository.save(alert).getId();
    }

    private static UUID extractJobId(String responseBody) {
        int start = responseBody.indexOf("\"id\":\"") + 6;
        int end = responseBody.indexOf('"', start);
        return UUID.fromString(responseBody.substring(start, end));
    }

    private void awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        Job job = jobRepository.findById(id).orElseThrow();
        assertThat(job.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
    }

    private String registerAndLogin(String email) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", email, "password", "correct-horse-battery", "displayName", "T6 Tester"))))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("token").asText();
    }

}
