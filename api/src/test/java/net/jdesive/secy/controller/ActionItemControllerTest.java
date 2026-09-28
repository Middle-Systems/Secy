package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.*;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code POST/GET/PATCH /action-items}, its {@code /findings}, {@code /comments} and
 * {@code /history} sub-resources — the M1j status machine end to end via MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ActionItemControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository compromiseRepository;

    @Autowired
    private ActionItemRepository actionItemRepository;

    @Autowired
    private ActionItemFindingRepository actionItemFindingRepository;

    @Autowired
    private ActionItemEventRepository actionItemEventRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private TenantRepository tenantRepository;

    private String token;
    private UUID productId;
    private UUID otherProductId;
    private UUID vulnHigh;
    private UUID vulnLow;
    private UUID vulnUnscored;
    private UUID compromiseId;
    private UUID otherProductVulnId;
    private UUID assigneeId;
    private UUID disabledUserId;

    @BeforeEach
    void seed() throws Exception {
        actionItemEventRepository.deleteAll();
        actionItemFindingRepository.deleteAll();
        actionItemRepository.deleteAll();
        compromiseRepository.deleteAll();
        alertRepository.deleteAll();
        userRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();

        token = registerAndLogin("action-item-tester@example.com", "correct-horse-battery", "Action Item Tester");

        Product product = new Product();
        product.setName("Acme Action Items " + UUID.randomUUID());
        productId = productRepository.save(product).getId();

        Product otherProduct = new Product();
        otherProduct.setName("Acme Other " + UUID.randomUUID());
        otherProductId = productRepository.save(otherProduct).getId();

        SBOMComponent component = seedComponent(productId);
        SBOMComponent otherComponent = seedComponent(otherProductId);

        vulnHigh = seedAlert(component, "CVE-2099-1001", 80.0);
        vulnLow = seedAlert(component, "CVE-2099-1002", 40.0);
        vulnUnscored = seedAlert(component, "CVE-2099-1003", null);
        compromiseId = seedCompromise(component, "MAL-2099-1001");
        otherProductVulnId = seedAlert(otherComponent, "CVE-2099-2001", 10.0);

        User assignee = new User();
        assignee.setEmail("ai-assignee@example.com");
        assignee.setPasswordHash("{noop}unused");
        assignee.setDisplayName("Assignee Person");
        assignee.setRole(Role.USER);
        assignee.setEnabled(true);
        assignee = userRepository.save(assignee);
        assigneeId = assignee.getId();
        addToDefaultTenant(assignee);

        User disabled = new User();
        disabled.setEmail("ai-disabled@example.com");
        disabled.setPasswordHash("{noop}unused");
        disabled.setDisplayName("Disabled Person");
        disabled.setRole(Role.USER);
        disabled.setEnabled(false);
        disabledUserId = userRepository.save(disabled).getId();
    }

    /** New users don't automatically join the tenant the way registration does; mirror it here. */
    private void addToDefaultTenant(User user) {
        Tenant tenant = tenantRepository.findById(Tenant.DEFAULT_TENANT_ID).orElseThrow();
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        tenantMembershipRepository.save(membership);
    }

    /* ------------------------------------------------------------------ */
    /* Create                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void createDerivesScopeAndRecordsCreatedPlusAttachedEvents() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Upgrade log4j",
                "description", "Bump to a fixed version",
                "findings", List.of(
                        Map.of("type", "VULNERABILITY", "id", vulnHigh.toString()),
                        Map.of("type", "COMPROMISE", "id", compromiseId.toString()))));

        MvcResult result = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.productId").value(productId.toString()))
                .andExpect(jsonPath("$.assetId").doesNotExist())
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.recordedStatus").value("OPEN"))
                .andExpect(jsonPath("$.findingCount").value(2))
                .andExpect(jsonPath("$.findings", hasSize(2)))
                .andReturn();

        UUID itemId = idFrom(result);

        List<ActionItemEvent> events = actionItemEventRepository.findAllByActionItemIdOrderByCreatedAtAsc(itemId);
        assertThat(events).hasSize(3);
        assertThat(events.get(0).getEventType()).isEqualTo(ActionItemEventType.CREATED);
        assertThat(events.get(1).getEventType()).isEqualTo(ActionItemEventType.FINDING_ATTACHED);
        assertThat(events.get(2).getEventType()).isEqualTo(ActionItemEventType.FINDING_ATTACHED);
    }

    @Test
    void createRejectsBlankTitle() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "  ",
                "findings", List.of(Map.of("type", "VULNERABILITY", "id", vulnHigh.toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRejectsEmptyFindings() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("title", "Nothing to fix", "findings", List.of()));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRejectsAProvenanceRef() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Provenance", "findings", List.of(Map.of("type", "PROVENANCE", "id", UUID.randomUUID().toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRejectsAnUnknownFinding() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Unknown", "findings", List.of(Map.of("type", "VULNERABILITY", "id", UUID.randomUUID().toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRejectsFindingsSpanningMoreThanOneScope() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Cross-product",
                "findings", List.of(
                        Map.of("type", "VULNERABILITY", "id", vulnHigh.toString()),
                        Map.of("type", "VULNERABILITY", "id", otherProductVulnId.toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRejectsAnUnknownAssignee() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Bad assignee", "assigneeUserId", UUID.randomUUID().toString(),
                "findings", List.of(Map.of("type", "VULNERABILITY", "id", vulnHigh.toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createConflictsWhenAFindingIsAlreadyLinked() throws Exception {
        createItem("First item", List.of(ref("VULNERABILITY", vulnHigh)), null);

        String body = objectMapper.writeValueAsString(Map.of(
                "title", "Second item", "findings", List.of(Map.of("type", "VULNERABILITY", "id", vulnHigh.toString()))));
        mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());
    }

    /* ------------------------------------------------------------------ */
    /* PATCH status machine                                                */
    /* ------------------------------------------------------------------ */

    @Test
    void patchWalksTheStatusMachine() throws Exception {
        UUID itemId = createItem("Walk item", List.of(ref("VULNERABILITY", vulnHigh)), null);

        patchStatus(itemId, Map.of("status", "IN_PROGRESS")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"));

        LocalDateTime until = LocalDateTime.now().plusDays(30);
        patchStatus(itemId, Map.of("status", "RISK_ACCEPTED", "riskAcceptedUntil", until.toString(),
                "riskAcceptanceJustification", "Accepted for now"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RISK_ACCEPTED"))
                .andExpect(jsonPath("$.riskAcceptance.justification").value("Accepted for now"));

        ActionItem afterAccept = actionItemRepository.findById(itemId).orElseThrow();
        assertThat(afterAccept.getRiskAcceptedUntil()).isNotNull();
        assertThat(afterAccept.getRiskAcceptedById()).isNotNull();

        patchStatus(itemId, Map.of("status", "OPEN")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OPEN"));

        ActionItem afterReopen = actionItemRepository.findById(itemId).orElseThrow();
        assertThat(afterReopen.getRiskAcceptedUntil()).isNull();
        assertThat(afterReopen.getRiskAcceptedById()).isNull();

        patchStatus(itemId, Map.of("status", "RESOLVED")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESOLVED"));
        ActionItem afterResolve = actionItemRepository.findById(itemId).orElseThrow();
        assertThat(afterResolve.getResolvedAt()).isNotNull();

        patchStatus(itemId, Map.of("status", "IN_PROGRESS")).andExpect(status().isOk());
        ActionItem afterReopen2 = actionItemRepository.findById(itemId).orElseThrow();
        assertThat(afterReopen2.getResolvedAt()).isNull();

        List<ActionItemEvent> events = actionItemEventRepository.findAllByActionItemIdOrderByCreatedAtAsc(itemId);
        List<ActionItemEvent> statusEvents = events.stream()
                .filter(e -> e.getEventType() == ActionItemEventType.STATUS_CHANGED).toList();
        assertThat(statusEvents).hasSize(5);
        assertThat(statusEvents.get(0).getFromStatus()).isEqualTo(RemediationStatus.OPEN);
        assertThat(statusEvents.get(0).getToStatus()).isEqualTo(RemediationStatus.IN_PROGRESS);
    }

    @Test
    void patchRejectsNotAffected() throws Exception {
        UUID itemId = createItem("NA item", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "NOT_AFFECTED")).andExpect(status().isBadRequest());
    }

    @Test
    void patchRejectsRiskAcceptedWithPastUntil() throws Exception {
        UUID itemId = createItem("Past until", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "RISK_ACCEPTED",
                "riskAcceptedUntil", LocalDateTime.now().minusDays(1).toString(),
                "riskAcceptanceJustification", "justified"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void patchRejectsRiskAcceptedWithMissingUntil() throws Exception {
        UUID itemId = createItem("Missing until", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "RISK_ACCEPTED", "riskAcceptanceJustification", "justified"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void patchRejectsRiskAcceptedWithBlankJustification() throws Exception {
        UUID itemId = createItem("Blank justification", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "RISK_ACCEPTED",
                "riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString(), "riskAcceptanceJustification", "   "))
                .andExpect(status().isBadRequest());
    }

    @Test
    void patchRejectsRiskFieldsWithoutRiskAcceptedStatus() throws Exception {
        UUID itemId = createItem("Loose risk fields", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void patchAllowsApproverToEqualAcceptor() throws Exception {
        UUID itemId = createItem("Self approve", List.of(ref("VULNERABILITY", vulnHigh)), null);
        User tester = userRepository.findByEmail("action-item-tester@example.com").orElseThrow();
        Map<String, Object> body = new HashMap<>();
        body.put("status", "RISK_ACCEPTED");
        body.put("riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString());
        body.put("riskAcceptanceJustification", "self-accepted");
        body.put("riskApprovedByUserId", tester.getId().toString());
        patchStatus(itemId, body).andExpect(status().isOk())
                .andExpect(jsonPath("$.riskAcceptance.approvedById").value(tester.getId().toString()));
    }

    @Test
    void patchRejectsADisabledApprover() throws Exception {
        UUID itemId = createItem("Disabled approver", List.of(ref("VULNERABILITY", vulnHigh)), null);
        Map<String, Object> body = new HashMap<>();
        body.put("status", "RISK_ACCEPTED");
        body.put("riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString());
        body.put("riskAcceptanceJustification", "justified");
        body.put("riskApprovedByUserId", disabledUserId.toString());
        patchStatus(itemId, body).andExpect(status().isBadRequest());
    }

    @Test
    void patchAssignsAndUnassigns() throws Exception {
        UUID itemId = createItem("Assignment", List.of(ref("VULNERABILITY", vulnHigh)), null);

        patchStatus(itemId, Map.of("assigneeUserId", assigneeId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assigneeId").value(assigneeId.toString()));

        patchStatus(itemId, Map.of("unassign", true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assigneeId").doesNotExist());
    }

    @Test
    void patchRejectsAssigneeAndUnassignTogether() throws Exception {
        UUID itemId = createItem("Both", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("assigneeUserId", assigneeId.toString(), "unassign", true))
                .andExpect(status().isBadRequest());
    }

    /* ------------------------------------------------------------------ */
    /* Attach / detach                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void attachToAResolvedItemIs409() throws Exception {
        UUID itemId = createItem("Resolved", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "RESOLVED")).andExpect(status().isOk());

        String body = objectMapper.writeValueAsString(Map.of(
                "findings", List.of(Map.of("type", "VULNERABILITY", "id", vulnLow.toString()))));
        mockMvc.perform(post("/action-items/{id}/findings", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void attachToARiskAcceptedItemIs409() throws Exception {
        UUID itemId = createItem("RA", List.of(ref("VULNERABILITY", vulnHigh)), null);
        patchStatus(itemId, Map.of("status", "RISK_ACCEPTED",
                "riskAcceptedUntil", LocalDateTime.now().plusDays(30).toString(), "riskAcceptanceJustification", "ok"))
                .andExpect(status().isOk());

        String body = objectMapper.writeValueAsString(Map.of(
                "findings", List.of(Map.of("type", "VULNERABILITY", "id", vulnLow.toString()))));
        mockMvc.perform(post("/action-items/{id}/findings", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void attachRejectsAScopeMismatch() throws Exception {
        UUID itemId = createItem("Scope", List.of(ref("VULNERABILITY", vulnHigh)), null);
        String body = objectMapper.writeValueAsString(Map.of(
                "findings", List.of(Map.of("type", "VULNERABILITY", "id", otherProductVulnId.toString()))));
        mockMvc.perform(post("/action-items/{id}/findings", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void detachThenDetachAgainIs404() throws Exception {
        UUID itemId = createItem("Detach", List.of(ref("VULNERABILITY", vulnHigh), ref("COMPROMISE", compromiseId)), null);

        mockMvc.perform(delete("/action-items/{id}/findings/{type}/{findingId}", itemId, "VULNERABILITY", vulnHigh)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNoContent());

        mockMvc.perform(delete("/action-items/{id}/findings/{type}/{findingId}", itemId, "VULNERABILITY", vulnHigh)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(1));
    }

    /* ------------------------------------------------------------------ */
    /* Comments / history                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    void commentsAndHistoryAreOrderedAndAttributed() throws Exception {
        UUID itemId = createItem("History", List.of(ref("VULNERABILITY", vulnHigh)), null);

        mockMvc.perform(post("/action-items/{id}/comments", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("comment", "checking in"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.comment").value("checking in"))
                .andExpect(jsonPath("$.changedByName").value("Action Item Tester"));

        mockMvc.perform(get("/action-items/{id}/history", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("CREATED"))
                .andExpect(jsonPath("$[1].eventType").value("FINDING_ATTACHED"))
                .andExpect(jsonPath("$[2].eventType").value("COMMENTED"))
                .andExpect(jsonPath("$[2].comment").value("checking in"));
    }

    /* ------------------------------------------------------------------ */
    /* List                                                                */
    /* ------------------------------------------------------------------ */

    @Test
    void listDefaultHidesResolvedNotAffectedAndRiskAccepted() throws Exception {
        UUID open = createItem("Open item", List.of(ref("VULNERABILITY", vulnUnscored)), null);
        UUID resolved = createItem("Resolved item", List.of(ref("VULNERABILITY", vulnLow)), null);
        patchStatus(resolved, Map.of("status", "RESOLVED")).andExpect(status().isOk());

        mockMvc.perform(get("/action-items").param("productId", productId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id=='" + open + "')]", hasSize(1)))
                .andExpect(jsonPath("$.content[?(@.id=='" + resolved + "')]", hasSize(0)));

        mockMvc.perform(get("/action-items").param("status", "RESOLVED")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id=='" + resolved + "')]", hasSize(1)));
    }

    @Test
    void listFiltersByProductAssigneeAndAssetSeparately() throws Exception {
        UUID item = createItem("Assignable", List.of(ref("VULNERABILITY", vulnUnscored)), assigneeId);

        mockMvc.perform(get("/action-items").param("assigneeUserId", assigneeId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id=='" + item + "')]", hasSize(1)));

        mockMvc.perform(get("/action-items").param("productId", otherProductId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id=='" + item + "')]", hasSize(0)));
    }

    /* ------------------------------------------------------------------ */
    /* Score                                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void scoreIsMaxOfLinkedVulnerabilitiesAndCompromiseCountsButDoesNotScore() throws Exception {
        UUID itemId = createItem("Scored", List.of(
                ref("VULNERABILITY", vulnHigh), ref("VULNERABILITY", vulnLow), ref("VULNERABILITY", vulnUnscored),
                ref("COMPROMISE", compromiseId)), null);

        mockMvc.perform(get("/action-items/{id}", itemId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score.riskScore").value(80.0))
                .andExpect(jsonPath("$.score.topFindingId").value(vulnHigh.toString()))
                .andExpect(jsonPath("$.score.scoredVulnerabilityCount").value(2))
                .andExpect(jsonPath("$.score.unscoredVulnerabilityCount").value(1))
                .andExpect(jsonPath("$.findingCountsByType.COMPROMISE").value(1));
    }

    /* ------------------------------------------------------------------ */
    /* Spring Data REST exposure check                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void springDataRestDoesNotExposeTheNewRepositories() throws Exception {
        mockMvc.perform(get("/actionItems").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/actionItemFindings").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/actionItemEvents").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private Map<String, String> ref(String type, UUID id) {
        Map<String, String> m = new HashMap<>();
        m.put("type", type);
        m.put("id", id.toString());
        return m;
    }

    private UUID createItem(String title, List<Map<String, String>> findings, UUID assignee) throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("title", title);
        body.put("findings", findings);
        if (assignee != null) {
            body.put("assigneeUserId", assignee.toString());
        }
        MvcResult result = mockMvc.perform(post("/action-items")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andReturn();
        return idFrom(result);
    }

    private org.springframework.test.web.servlet.ResultActions patchStatus(UUID itemId, Map<String, ?> body) throws Exception {
        return mockMvc.perform(patch("/action-items/{id}", itemId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));
    }

    private UUID idFrom(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return UUID.fromString(body.get("id").asText());
    }

    private SBOMComponent seedComponent(UUID forProductId) {
        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1-" + UUID.randomUUID());
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(productRepository.findById(forProductId).orElseThrow());
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);
        return component;
    }

    private UUID seedAlert(SBOMComponent component, String cveId, Double riskScore) {
        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded by ActionItemControllerTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alert.setRiskScore(riskScore);
        return alertRepository.save(alert).getId();
    }

    private UUID seedCompromise(SBOMComponent component, String iocId) {
        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId(iocId);
        finding.setMatchedOn("pkg:npm/evil-pkg@1.0.0");
        finding.setSummary("Malicious code in evil-pkg (npm)");
        return compromiseRepository.save(finding).getId();
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
