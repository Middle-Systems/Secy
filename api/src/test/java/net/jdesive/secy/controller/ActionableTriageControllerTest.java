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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Phase 7's triage surface on {@code ActionableController}: {@code PATCH /actionable/{id}},
 * {@code POST /actionable/{id}/comments}, the bulk {@code PATCH /actionable}, and
 * {@code GET /actionable/{id}/history}.
 *
 * <p>Every request here carries a real bearer token from {@code /auth/register} rather than
 * {@code @WithMockUser}: the triage endpoints resolve {@code @AuthenticationPrincipal AppUserPrincipal}
 * and attribute every {@code TriageEvent} to it, and {@code @WithMockUser}'s principal is a plain
 * Spring Security {@code User}, not an {@code AppUserPrincipal} — {@code @AuthenticationPrincipal}
 * would silently resolve it to null.
 *
 * <p>{@code @Transactional}: the H2 database is shared across every {@code @SpringBootTest} context
 * in the run, and a {@code TriageEvent} is cleared before the alert/finding rows it references, same
 * as every other {@code @BeforeEach} here.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ActionableTriageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private TriageEventRepository eventRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    private String token;
    private UUID alertId;
    private UUID findingId;
    private UUID assigneeId;

    @BeforeEach
    void seed() throws Exception {
        eventRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        userRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();

        token = registerAndLogin("triage-tester@example.com", "correct-horse-battery", "Triage Tester");

        User assignee = new User();
        assignee.setEmail("assignee@example.com");
        assignee.setPasswordHash("{noop}unused");
        assignee.setDisplayName("Assignee Person");
        assignee.setRole(Role.USER);
        assignee.setEnabled(true);
        assigneeId = userRepository.save(assignee).getId();

        Product product = new Product();
        product.setName("Acme Web");
        productRepository.save(product);

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
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
        cve.setId("CVE-2099-9101");
        cve.setDescription("Seeded by ActionableTriageControllerTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        // save() on an entity with an assigned (non-generated) id merges rather than persists, and
        // merge() returns a NEW managed instance — the original reference stays transient. Reassign,
        // or VulnerabilityAlert.vulnerability ends up pointing at an unsaved transient instance.
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alertId = alertRepository.save(alert).getId();

        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId("MAL-2099-0101");
        finding.setMatchedOn("pkg:npm/evil-pkg@1.0.0");
        finding.setSummary("Malicious code in evil-pkg (npm)");
        findingId = findingRepository.save(finding).getId();
    }

    /* ------------------------------------------------------------------ */
    /* PATCH /actionable/{id}                                             */
    /* ------------------------------------------------------------------ */

    @Test
    void patchUpdatesStateAssigneeAndSnoozeOnAVulnerabilityAlert() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "state", "ACKNOWLEDGED",
                "assigneeId", assigneeId.toString(),
                "comment", "Triaging now"));

        mockMvc.perform(patch("/actionable/{id}", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(alertId.toString()))
                .andExpect(jsonPath("$.itemType").value("VULNERABILITY"))
                .andExpect(jsonPath("$.triageState").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$.assigneeId").value(assigneeId.toString()))
                .andExpect(jsonPath("$.assigneeName").value("Assignee Person"));

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(reloaded.getAssignee().getId()).isEqualTo(assigneeId);

        List<TriageEvent> events = eventRepository.findAllByVulnerabilityAlertIdOrderByCreatedAtAsc(alertId);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getComment()).isEqualTo("Triaging now");
    }

    @Test
    void patchAVulnerabilityIdIsCrossCheckedAgainstTheCompromiseTableToo() throws Exception {
        // The resolver-across-both-tables contract: a compromise finding id works here even though
        // GET /actionable/{id} would 404 it.
        String body = objectMapper.writeValueAsString(Map.of("state", "RESOLVED"));

        mockMvc.perform(patch("/actionable/{id}", findingId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(findingId.toString()))
                .andExpect(jsonPath("$.itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.triageState").value("RESOLVED"));

        // Confirm the GET detail endpoint really is vulnerability-only, as documented — the contrast
        // that makes the assertion above meaningful.
        mockMvc.perform(get("/actionable/{id}", findingId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());

        CompromiseFinding reloaded = findingRepository.findById(findingId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.RESOLVED);
    }

    @Test
    void patchAnUnknownIdIs404() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("state", "ACKNOWLEDGED"));

        mockMvc.perform(patch("/actionable/{id}", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* POST /actionable/{id}/comments                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void postCommentRecordsAStandaloneHistoryEntry() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("comment", "Confirmed exploitable in our environment"));

        mockMvc.perform(post("/actionable/{id}/comments", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.comment").value("Confirmed exploitable in our environment"))
                .andExpect(jsonPath("$.fromState").doesNotExist())
                .andExpect(jsonPath("$.toState").doesNotExist());

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.OPEN);
    }

    @Test
    void postCommentRejectsABlankBody() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("comment", "   "));

        mockMvc.perform(post("/actionable/{id}/comments", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postCommentOnAnUnknownIdIs404() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("comment", "irrelevant"));

        mockMvc.perform(post("/actionable/{id}/comments", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* PATCH /actionable (bulk)                                           */
    /* ------------------------------------------------------------------ */

    @Test
    void bulkPatchUpdatesAMixOfBothArmsAndSkipsAnUnknownId() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ids", List.of(alertId.toString(), findingId.toString(), UUID.randomUUID().toString()),
                "state", "ACKNOWLEDGED"));

        mockMvc.perform(patch("/actionable")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.updated").value(2));

        assertThat(alertRepository.findById(alertId).orElseThrow().getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);
        assertThat(findingRepository.findById(findingId).orElseThrow().getTriageState()).isEqualTo(TriageState.ACKNOWLEDGED);
    }

    /* ------------------------------------------------------------------ */
    /* GET /actionable/{id}/history                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void historyReturnsEventsOldestFirst() throws Exception {
        mockMvc.perform(patch("/actionable/{id}", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("state", "ACKNOWLEDGED", "comment", "first"))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/actionable/{id}/comments", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("comment", "second"))))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/actionable/{id}/history", alertId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", org.hamcrest.Matchers.hasSize(2)))
                .andExpect(jsonPath("$[0].comment").value("first"))
                .andExpect(jsonPath("$[0].toState").value("ACKNOWLEDGED"))
                .andExpect(jsonPath("$[1].comment").value("second"))
                .andExpect(jsonPath("$[1].toState").doesNotExist());
    }

    @Test
    void historyForAnUnknownIdIs404() throws Exception {
        mockMvc.perform(get("/actionable/{id}/history", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Auth helper                                                        */
    /* ------------------------------------------------------------------ */

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
