package net.jdesive.secy.actionitem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.ActionItemEventRepository;
import net.jdesive.secy.persistence.ActionItemFindingRepository;
import net.jdesive.secy.persistence.ActionItemRepository;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexPrecedenceConfigRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionItem;
import net.jdesive.secy.persistence.entity.ActionItemEvent;
import net.jdesive.secy.persistence.entity.ActionItemEventType;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The three M1j acceptance scenarios named in the plan, plus the vulnerability-reappearance
 * counterpart of (a) — grouping/auto-reopen via real drift reappearance, VEX not-affected (the M1
 * acceptance criterion), risk-acceptance expiry, and vulnerability reappearance via
 * {@code CorrelationService}. Modeled on {@code LifecycleDriftAcceptanceTest}/{@code VexAcceptanceTest}'s
 * upload/poll/await-terminal pattern — deliberately NOT {@code @Transactional}, since drift/VEX effects
 * only become observable once their job's transaction actually commits.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ActionItemAcceptanceTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);
    private static final String LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

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
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private CompromiseFindingRepository compromiseFindingRepository;

    @Autowired
    private LifecycleDriftFindingRepository lifecycleDriftFindingRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @Autowired
    private VexPrecedenceConfigRepository vexPrecedenceConfigRepository;

    @Autowired
    private ActionItemEventRepository actionItemEventRepository;

    @Autowired
    private ActionItemFindingRepository actionItemFindingRepository;

    @Autowired
    private ActionItemRepository actionItemRepository;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private CorrelationService correlationService;

    private UUID productId;
    private String token;

    @BeforeEach
    void seed() throws Exception {
        // The H2 database is shared by every @SpringBootTest context in the run.
        actionItemEventRepository.deleteAll();
        actionItemFindingRepository.deleteAll();
        actionItemRepository.deleteAll();
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        vexPrecedenceConfigRepository.deleteAll();
        lifecycleDriftFindingRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        epssRepository.deleteAll();
        osvRepository.deleteAll();
        userRepository.deleteAll();

        Product product = new Product();
        product.setName("action-item-acceptance-" + UUID.randomUUID());
        productId = productRepository.save(product).getId();

        token = registerAndLogin("ai-acceptance@example.com", "correct-horse-battery", "Acceptance Tester");
    }

    @AfterEach
    void resetPrecedenceConfig() {
        vexPrecedenceConfigRepository.deleteAll();
    }

    /* ------------------------------------------------------------------ */
    /* (a) Grouping + auto-reopen via real drift reappearance              */
    /* ------------------------------------------------------------------ */

    @Test
    void groupingAndAutoReopenViaRealDriftReappearance() throws Exception {
        uploadSbomAndAwait("source.cdx.json");
        uploadSbomAndAwait("build-two-injected.cdx.json");

        List<LifecycleDriftFinding> findings = lifecycleDriftFindingRepository.findAll();
        assertThat(findings).hasSize(2);
        UUID utilsFindingId = findings.stream()
                .filter(f -> f.getIdentityKey().equals("npm/acme-internal-utils")).findFirst().orElseThrow().getId();
        UUID secretsFindingId = findings.stream()
                .filter(f -> f.getIdentityKey().equals("npm/acme-internal-secrets")).findFirst().orElseThrow().getId();

        MvcResult createResult = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "title", "Investigate build-only components",
                                "findings", List.of(
                                        Map.of("type", "LIFECYCLE_DRIFT", "id", utilsFindingId.toString()),
                                        Map.of("type", "LIFECYCLE_DRIFT", "id", secretsFindingId.toString()))))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.productId").value(productId.toString()))
                .andExpect(jsonPath("$.assetId").doesNotExist())
                .andReturn();
        UUID itemId = idFrom(createResult);

        uploadSbomAndAwait("build-clean.cdx.json");

        assertThat(lifecycleDriftFindingRepository.findById(utilsFindingId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
        assertThat(lifecycleDriftFindingRepository.findById(secretsFindingId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        mockMvc.perform(get("/action-items/{id}", itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fixVerified").value(true));

        mockMvc.perform(patch("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "RESOLVED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESOLVED"));

        // Backdate resolvedAt by 1 second, ruling out same-microsecond flakiness on the reopen boundary.
        ActionItem item = actionItemRepository.findById(itemId).orElseThrow();
        item.setResolvedAt(item.getResolvedAt().minusSeconds(1));
        actionItemRepository.save(item);

        uploadSbomAndAwait("build-one-back.cdx.json");

        assertThat(lifecycleDriftFindingRepository.findById(utilsFindingId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(lifecycleDriftFindingRepository.findById(secretsFindingId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        mockMvc.perform(get("/action-items/{id}", itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.recordedStatus").value("RESOLVED"))
                .andExpect(jsonPath("$.reopened").value(true))
                .andExpect(jsonPath("$.derivation").value("REOPENED_ON_REAPPEARANCE"))
                .andExpect(jsonPath("$.reopenedFindings", hasSize(1)))
                .andExpect(jsonPath("$.reopenedFindings[0].id").value(utilsFindingId.toString()));

        mockMvc.perform(patch("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "IN_PROGRESS"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"));

        List<ActionItemEvent> events = actionItemEventRepository.findAllByActionItemIdOrderByCreatedAtAsc(itemId);
        ActionItemEvent last = events.get(events.size() - 1);
        assertThat(last.getEventType()).isEqualTo(ActionItemEventType.STATUS_CHANGED);
        assertThat(last.getFromStatus()).isEqualTo(RemediationStatus.OPEN);
        assertThat(last.getDerivation().name()).isEqualTo("REOPENED_ON_REAPPEARANCE");
    }

    /* ------------------------------------------------------------------ */
    /* (b) VEX not-affected -- the M1 acceptance criterion                 */
    /* ------------------------------------------------------------------ */

    @Test
    void vexNotAffectedMovesTheFindingAndTheItemToNotAffected() throws Exception {
        UUID alertId = seedVulnerabilityAlert("CVE-2099-7001", LOG4J_PURL);

        MvcResult createResult = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "title", "Track log4j exposure",
                                "findings", List.of(Map.of("type", "VULNERABILITY", "id", alertId.toString()))))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID itemId = idFrom(createResult);

        uploadVexAndAwait("TENANT", body("openvex-tenant-not-affected.json"));

        // Finding-level precedence: VEX beats "linked to an action item" (rule 2 before rule 3 --
        // see RemediationStatusDeriver.forFinding), so the basis is VEX here, not ACTION_ITEM.
        mockMvc.perform(get("/findings/{type}/{id}", "VULNERABILITY", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.statusBasis").value("VEX"))
                .andExpect(jsonPath("$.vexJustification").isNotEmpty());

        mockMvc.perform(get("/action-items/{id}", itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.derivation").value("VEX_NOT_AFFECTED"));
    }

    /* ------------------------------------------------------------------ */
    /* (c) Risk-acceptance expiry                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void riskAcceptanceExpiryReopensTheItem() throws Exception {
        UUID alertId = seedVulnerabilityAlert("CVE-2099-7002", LOG4J_PURL);

        MvcResult createResult = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "title", "Risk-accept for now",
                                "findings", List.of(Map.of("type", "VULNERABILITY", "id", alertId.toString()))))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID itemId = idFrom(createResult);

        Map<String, Object> acceptBody = new HashMap<>();
        acceptBody.put("status", "RISK_ACCEPTED");
        acceptBody.put("riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString());
        acceptBody.put("riskAcceptanceJustification", "Compensating control in place");
        mockMvc.perform(patch("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(acceptBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RISK_ACCEPTED"));

        // Set the expiry directly in the past through the repository -- deterministic, preferred over waiting.
        ActionItem item = actionItemRepository.findById(itemId).orElseThrow();
        item.setRiskAcceptedUntil(LocalDateTime.now().minusDays(1));
        actionItemRepository.save(item);

        mockMvc.perform(get("/action-items/{id}", itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.recordedStatus").value("RISK_ACCEPTED"))
                .andExpect(jsonPath("$.riskAcceptanceExpired").value(true));

        mockMvc.perform(get("/action-items").param("productId", productId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id=='" + itemId + "')]", hasSize(1)));
    }

    /* ------------------------------------------------------------------ */
    /* (d) Vulnerability reappearance via CorrelationService, direct       */
    /* ------------------------------------------------------------------ */

    @Test
    void vulnerabilityReappearanceReopensTheItemWithNoWriteThroughToTriage() throws Exception {
        String cveId = "CVE-2099-7003";
        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded for ActionItemAcceptanceTest");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        EPSS epss = new EPSS();
        epss.setCve(cveId);
        epss.setEpss(0.9f);
        epss.setPercentile(0.99f);
        epss.setDate(LocalDateTime.now());
        epssRepository.save(epss);

        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId("GHSA-reappear");
        advisory.setEcosystem("npm");
        advisory.setPackageName("acme-reappear-pkg");
        advisory.setModified(LocalDateTime.now());
        advisory.getAliases().add(cveId);
        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("SEMVER");
        range.setIntroduced("0");
        range.setFixed("2.0.0");
        advisory.getRanges().add(range);
        osvRepository.save(advisory);

        Product product = productRepository.findById(productId).orElseThrow();

        UUID vulnerableSbomId = sbomWithComponent(product, "acme-reappear-pkg", "1.0.0",
                "pkg:npm/acme-reappear-pkg@1.0.0");
        correlate(vulnerableSbomId);

        List<VulnerabilityAlert> alerts = alertRepository.findAllBySbomIdForCorrelation(vulnerableSbomId);
        assertThat(alerts).hasSize(1);
        UUID alertId = alerts.get(0).getId();
        TriageState triageBefore = alerts.get(0).getTriageState();

        MvcResult createResult = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "title", "Upgrade acme-reappear-pkg",
                                "findings", List.of(Map.of("type", "VULNERABILITY", "id", alertId.toString()))))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID itemId = idFrom(createResult);

        JsonNode actionableBefore = actionableSnapshot();

        // Fixed: a new SBOM for the same product without the vulnerable version auto-resolves the alert.
        UUID fixedSbomId = sbomWithComponent(product, "acme-reappear-pkg", "2.0.0",
                "pkg:npm/acme-reappear-pkg@2.0.0");
        correlate(fixedSbomId);
        assertThat(alertRepository.findById(alertId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        mockMvc.perform(patch("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "RESOLVED"))))
                .andExpect(status().isOk());

        ActionItem item = actionItemRepository.findById(itemId).orElseThrow();
        item.setResolvedAt(item.getResolvedAt().minusSeconds(1));
        actionItemRepository.save(item);

        // Vulnerable again: correlation revives the same alert row with a fresh lastSeenAt.
        UUID vulnerableAgainSbomId = sbomWithComponent(product, "acme-reappear-pkg", "1.0.1",
                "pkg:npm/acme-reappear-pkg@1.0.1");
        correlate(vulnerableAgainSbomId);
        assertThat(alertRepository.findById(alertId).orElseThrow().getLifecycleState())
                .isEqualTo(AlertLifecycleState.ACTIVE);

        mockMvc.perform(get("/action-items/{id}", itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.reopened").value(true))
                .andExpect(jsonPath("$.derivation").value("REOPENED_ON_REAPPEARANCE"));

        // No write-through: the alert's own triageState never moved through any of this.
        assertThat(alertRepository.findById(alertId).orElseThrow().getTriageState()).isEqualTo(triageBefore);

        // Same alert, same funnel verdict, same triage state -- action item operations never touch
        // /actionable's population or its per-row funnel/triage fields. (componentVersion legitimately
        // differs: correlation re-points the revived alert at the latest matching component -- that is
        // what a re-scan does, nothing to do with action items.)
        JsonNode actionableAfter = actionableSnapshot();
        assertThat(actionableAfter.get("totalElements").asInt()).isEqualTo(actionableBefore.get("totalElements").asInt());
        JsonNode beforeRow = actionableBefore.get("content").get(0);
        JsonNode afterRow = actionableAfter.get("content").get(0);
        assertThat(afterRow.get("id").asText()).isEqualTo(beforeRow.get("id").asText());
        assertThat(afterRow.get("actionableReason").asText()).isEqualTo(beforeRow.get("actionableReason").asText());
        assertThat(afterRow.get("triageState").asText()).isEqualTo(beforeRow.get("triageState").asText());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private JsonNode actionableSnapshot() throws Exception {
        String body = mockMvc.perform(get("/actionable").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body);
    }

    private CorrelationService.CorrelationSummary correlate(UUID sbomId) {
        // Not @Transactional (see the class Javadoc), so each step runs its own transaction: the
        // repository read below, then correlationService.correlate's own @Transactional method.
        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        return correlationService.correlate(sbom);
    }

    private UUID sbomWithComponent(Product product, String name, String version, String purl) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());

        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        component.setSbom(sbom);
        sbom.getComponents().add(component);

        return sbomRepository.saveAndFlush(sbom).getId();
    }

    private UUID seedVulnerabilityAlert(String cveId, String purl) {
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
        cve.setDescription("Seeded for ActionItemAcceptanceTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(10.0d);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setCreatedAt(LocalDateTime.now());
        alert.setLifecycleState(AlertLifecycleState.ACTIVE);
        alert.setActionable(true);
        alert.setCvssScore(10.0d);
        return alertRepository.save(alert).getId();
    }

    private void uploadSbomAndAwait(String fixture) throws Exception {
        String responseBody = mockMvc.perform(post("/sbom/{productId}/sboms", productId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .param("productVersion", "1.0.0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(sbomFixture(fixture)))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        UUID jobId = extractJobId(responseBody);
        jobRunner.poll();
        awaitJobTerminal(jobId);
    }

    private void uploadVexAndAwait(String origin, String documentBody) throws Exception {
        String responseBody = mockMvc.perform(post("/vex")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .param("origin", origin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(documentBody))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        UUID jobId = extractJobId(responseBody);
        jobRunner.poll();
        awaitJobTerminal(jobId);
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

    private static String sbomFixture(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/lifecycle/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("vex/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private UUID idFrom(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return UUID.fromString(body.get("id").asText());
    }

    private String registerAndLogin(String email, String password, String displayName) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", email, "password", password, "displayName", displayName))))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("token").asText();
    }

}
