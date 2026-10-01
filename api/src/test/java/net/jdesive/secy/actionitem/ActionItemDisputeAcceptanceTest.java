package net.jdesive.secy.actionitem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.ActionItemEventRepository;
import net.jdesive.secy.persistence.ActionItemFindingRepository;
import net.jdesive.secy.persistence.ActionItemRepository;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M1k's T5 — see ROADMAP.md's M1k section 10. Modeled on {@code ActionItemAcceptanceTest}'s
 * upload/poll/await-terminal pattern; deliberately NOT {@code @Transactional}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ActionItemDisputeAcceptanceTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);
    private static final String PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
    private static final String CVE_ID = "CVE-2099-9001";

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
    private CompromiseFindingRepository compromiseFindingRepository;

    @Autowired
    private ActionItemEventRepository actionItemEventRepository;

    @Autowired
    private ActionItemFindingRepository actionItemFindingRepository;

    @Autowired
    private ActionItemRepository actionItemRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private net.jdesive.secy.persistence.AssetRepository assetRepository;

    @BeforeEach
    void cleanUp() {
        actionItemEventRepository.deleteAll();
        actionItemFindingRepository.deleteAll();
        actionItemRepository.deleteAll();
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        jobRepository.deleteAll();
        tenantMembershipRepository.deleteAll();
        userRepository.deleteAll();
    }

    @AfterEach
    void cleanUpAfter() {
        // Also after the LAST test in this class, so no account leaks into a later test class that
        // relies on M0's "first registered account becomes ADMIN" bootstrap rule.
        actionItemEventRepository.deleteAll();
        actionItemFindingRepository.deleteAll();
        actionItemRepository.deleteAll();
        tenantMembershipRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void disputingAVulnerabilityScopesTheStatementToOneProductOnly() throws Exception {
        String token = registerAndLogin("t5-engineer@example.com");

        Product productA = newProduct("T5 Product A " + UUID.randomUUID());
        Product productB = newProduct("T5 Product B " + UUID.randomUUID());
        UUID alertA = seedAlert(productA.getId(), CVE_ID);
        UUID alertB = seedAlert(productB.getId(), CVE_ID);

        UUID itemId = createItem(token, "Dispute me", alertA);

        long jobsBefore = jobRepository.count();
        MvcResult disputeResult = mockMvc.perform(post("/action-items/" + itemId + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", alertA.toString(),
                                "justification", "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
                                "impactStatement", "Not reachable in our deployment"))))
                .andExpect(status().isAccepted())
                .andReturn();
        assertThat(jobRepository.count()).isEqualTo(jobsBefore + 1);

        List<net.jdesive.secy.persistence.entity.ActionItemEvent> events =
                actionItemEventRepository.findAllByActionItemIdOrderByCreatedAtAsc(itemId);
        net.jdesive.secy.persistence.entity.ActionItemEvent disputeEvent = events.stream()
                .filter(e -> e.getEventType() == net.jdesive.secy.persistence.entity.ActionItemEventType.DISPUTED)
                .findFirst().orElseThrow();
        assertThat(disputeEvent.getVexDocumentId()).isNotNull();

        UUID jobId = extractJobId(disputeResult.getResponse().getContentAsString());
        jobRunner.poll();
        awaitJobTerminal(jobId);

        VulnerabilityAlert reloadedA = alertRepository.findById(alertA).orElseThrow();
        assertThat(reloadedA.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(reloadedA.getRiskScore()).isEqualTo(0.0);

        VexStatement statement = vexStatementRepository.findAll().stream()
                .filter(s -> s.getCveId().equalsIgnoreCase(CVE_ID))
                .findFirst().orElseThrow();
        assertThat(statement.getOrigin()).isEqualTo(VexOrigin.TENANT);
        assertThat(statement.getAuthor()).isEqualToIgnoringCase("t5-engineer@example.com");
        assertThat(statement.getScopeProductId()).isEqualTo(productA.getId());

        mockMvc.perform(get("/action-items/" + itemId).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.derivation").value("VEX_NOT_AFFECTED"));

        // Product B's alert, same CVE, is unchanged -- proves product scope.
        VulnerabilityAlert reloadedB = alertRepository.findById(alertB).orElseThrow();
        assertThat(reloadedB.getVexStatus()).isNull();
    }

    @Test
    void findingNotAttachedToTheItemIs400() throws Exception {
        String token = registerAndLogin("t5-unattached@example.com");
        Product productA = newProduct("T5 Unattached A " + UUID.randomUUID());
        UUID alertA = seedAlert(productA.getId(), "CVE-2099-9002");
        UUID itemId = createItem(token, "Other item", alertA);
        UUID unattached = seedAlert(productA.getId(), "CVE-2099-9003");

        long jobsBefore = jobRepository.count();
        mockMvc.perform(post("/action-items/" + itemId + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", unattached.toString(), "impactStatement", "n/a"))))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void compromiseFindingIs400() throws Exception {
        String token = registerAndLogin("t5-compromise@example.com");
        Product productA = newProduct("T5 Compromise A " + UUID.randomUUID());
        SBOMComponent component = seedComponent(productA.getId());
        UUID compromiseId = seedCompromise(component);
        UUID itemId = createItem(token, "Compromise item", "COMPROMISE", compromiseId);

        long jobsBefore = jobRepository.count();
        mockMvc.perform(post("/action-items/" + itemId + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", compromiseId.toString(), "impactStatement", "n/a"))))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void assetDerivedVulnerabilityIs400() throws Exception {
        String token = registerAndLogin("t5-asset@example.com");
        net.jdesive.secy.persistence.entity.Asset asset = new net.jdesive.secy.persistence.entity.Asset();
        asset.setType(net.jdesive.secy.persistence.entity.AssetType.CONTAINER_IMAGE);
        asset.setName("t5-asset:" + UUID.randomUUID());
        net.jdesive.secy.persistence.entity.AssetComponent assetComponent = new net.jdesive.secy.persistence.entity.AssetComponent();
        assetComponent.setName("asset-lib");
        assetComponent.setVersion("1.0.0");
        assetComponent.setPurl(PURL);
        assetComponent.setAsset(asset);
        asset.getComponents().add(assetComponent);

        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2099-9004");
        cve.setDescription("Seeded asset alert");
        cve.setBaseSeverity("HIGH");
        cve = cveRepository.save(cve);

        VulnerabilityAlert assetAlert = new VulnerabilityAlert();
        assetAlert.setVulnerability(cve);
        assetAlert.setAssetComponent(assetComponent);
        assetAlert.setActionable(true);
        assetAlert.setActionableReason(ActionableReason.KEV);

        // Persist the asset graph before the alert that references it.
        assetRepository.saveAndFlush(asset);
        UUID assetAlertId = alertRepository.save(assetAlert).getId();

        UUID itemId = createItem(token, "Asset item", assetAlertId);

        long jobsBefore = jobRepository.count();
        mockMvc.perform(post("/action-items/" + itemId + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", assetAlertId.toString(), "impactStatement", "n/a"))))
                .andExpect(status().isBadRequest());
        assertThat(jobRepository.count()).isEqualTo(jobsBefore);
    }

    @Test
    void blankImpactStatementIs400() throws Exception {
        String token = registerAndLogin("t5-blank@example.com");
        Product productA = newProduct("T5 Blank A " + UUID.randomUUID());
        UUID alertA = seedAlert(productA.getId(), "CVE-2099-9005");
        UUID itemId = createItem(token, "Blank item", alertA);

        mockMvc.perform(post("/action-items/" + itemId + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", alertA.toString(), "impactStatement", "   "))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unknownItemIs404() throws Exception {
        String token = registerAndLogin("t5-unknown@example.com");

        mockMvc.perform(post("/action-items/" + UUID.randomUUID() + "/disputes")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "findingId", UUID.randomUUID().toString(), "impactStatement", "n/a"))))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private Product newProduct(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.save(product);
    }

    private SBOMComponent seedComponent(UUID productId) {
        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl(PURL);
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(productRepository.findById(productId).orElseThrow());
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);
        return component;
    }

    private UUID seedAlert(UUID productId, String cveId) {
        SBOMComponent component = seedComponent(productId);

        Vulnerability cve = cveRepository.findById(cveId).orElseGet(() -> {
            Vulnerability v = new Vulnerability();
            v.setId(cveId);
            v.setDescription("Seeded by ActionItemDisputeAcceptanceTest");
            v.setBaseSeverity("CRITICAL");
            v.setCvssScore(9.8d);
            return cveRepository.save(v);
        });

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.EPSS_HIGH);
        alert.setEpssScore(0.5);
        alert.setRiskScore(55.0);
        return alertRepository.save(alert).getId();
    }

    private UUID seedCompromise(SBOMComponent component) {
        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId("MAL-T5-" + UUID.randomUUID());
        finding.setMatchedOn("pkg:npm/evil-pkg@1.0.0");
        finding.setSummary("Seeded malicious package");
        return compromiseFindingRepository.save(finding).getId();
    }

    private UUID createItem(String token, String title, UUID vulnerabilityAlertId) throws Exception {
        return createItem(token, title, "VULNERABILITY", vulnerabilityAlertId);
    }

    private UUID createItem(String token, String title, String findingType, UUID findingId) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", title,
                "findings", List.of(Map.of("type", findingType, "id", findingId.toString()))));
        MvcResult result = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText());
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
                                "email", email, "password", "correct-horse-battery", "displayName", "T5 Tester"))))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("token").asText();
    }

}
