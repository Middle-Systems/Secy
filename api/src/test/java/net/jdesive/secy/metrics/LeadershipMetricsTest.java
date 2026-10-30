package net.jdesive.secy.metrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.ActionItemRepository;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionItem;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.ProductService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** M1k's T7 — see ROADMAP.md's M1k section 10. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@WithMockUser
class LeadershipMetricsTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

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
    private ActionItemRepository actionItemRepository;

    @Autowired
    private AppUserRepository userRepository;

    private UUID cveCounter() {
        return UUID.randomUUID();
    }

    @Test
    void populationsAgreeAndCoverageReflectsEachProductsStageMix() throws Exception {
        // The H2 database is shared by every @SpringBootTest context in the run; a non-transactional
        // test class elsewhere may leave committed rows behind. Action items are scoped to this
        // (rolled-back) transaction's own tenant-wide read, so clear them first -- cheap and safe,
        // this class is @Transactional and rolls everything back regardless.
        actionItemRepository.deleteAll();

        User admin = new User();
        admin.setEmail("t7-admin@example.com");
        admin.setPasswordHash("{noop}unused");
        admin.setDisplayName("T7 Admin");
        admin.setRole(Role.ADMIN);
        admin.setEnabled(true);
        admin = userRepository.save(admin);

        // Baseline, before this test's own fixtures exist -- the KEV/severity assertions below
        // compare against this delta rather than an absolute count, since other already-committed
        // (non-transactional) test classes may have left their own KEV-reason alerts behind.
        MvcResult beforeResult = mockMvc.perform(get("/metrics/leadership")).andExpect(status().isOk()).andReturn();
        JsonNode before = objectMapper.readTree(beforeResult.getResponse().getContentAsString());
        long kevBefore = before.get("kevExposure").get("kevFindingCount").asLong();
        long kevPastDueBefore = before.get("kevExposure").get("kevPastDueCount").asLong();
        long kevDeployedBefore = before.get("kevExposure").get("kevByLifecycleStage").get("DEPLOYED").asLong();

        // Unassigned bucket must not appear in coverage.
        productService.getOrCreateUnassigned(Tenant.DEFAULT_TENANT_ID);

        Product p1 = newProduct("T7 P1 Staged " + UUID.randomUUID());
        Product p2 = newProduct("T7 P2 Legacy " + UUID.randomUUID());
        Product p3 = newProduct("T7 P3 NoSbom " + UUID.randomUUID());

        SBOMComponent sourceComponent = seedSbomComponent(p1.getId(), SbomLifecycleStage.SOURCE);
        SBOMComponent deployedComponent = seedSbomComponent(p1.getId(), SbomLifecycleStage.DEPLOYED);
        SBOMComponent legacyComponent = seedSbomComponent(p2.getId(), null);

        UUID criticalKevAlert = seedAlert(deployedComponent, "CRITICAL", true, LocalDate.now().plusDays(30));
        UUID pastDueKevAlert = seedAlert(deployedComponent, "HIGH", true, LocalDate.now().minusDays(5));
        UUID highNonKevAlert = seedAlert(legacyComponent, "HIGH", false, null);

        // Excluded from the KEV/severity population: a VEX not-affected KEV alert, an auto-resolved
        // alert, and a triage-resolved alert.
        UUID vexExcluded = seedAlert(deployedComponent, "CRITICAL", true, null);
        alertRepository.findById(vexExcluded).ifPresent(a -> {
            a.setVexStatus(VexStatus.NOT_AFFECTED);
            alertRepository.save(a);
        });
        UUID autoResolved = seedAlert(deployedComponent, "CRITICAL", true, null);
        alertRepository.findById(autoResolved).ifPresent(a -> {
            a.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            alertRepository.save(a);
        });
        UUID triageResolved = seedAlert(deployedComponent, "CRITICAL", true, null);
        alertRepository.findById(triageResolved).ifPresent(a -> {
            a.setTriageState(TriageState.RESOLVED);
            alertRepository.save(a);
        });

        // MTTR: two resolved items, 48h and 24h -> mean/median 36.
        LocalDateTime now = LocalDateTime.now();
        newResolvedItem(p1.getId(), admin.getId(), now.minusHours(48), now);
        newResolvedItem(p1.getId(), admin.getId(), now.minusHours(24), now);
        // Excluded: resolved 200 days ago (outside default 90-day window).
        newResolvedItem(p1.getId(), admin.getId(), now.minusDays(201), now.minusDays(200));

        MvcResult leadershipResult = mockMvc.perform(get("/metrics/leadership"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = objectMapper.readTree(leadershipResult.getResponse().getContentAsString());

        long severityTotal = body.get("findingsBySeverity").get("total").asLong();

        MvcResult actionableResult = mockMvc.perform(get("/actionable").param("itemType", "VULNERABILITY").param("size", "1"))
                .andExpect(status().isOk())
                .andReturn();
        long actionableTotal = objectMapper.readTree(actionableResult.getResponse().getContentAsString())
                .get("totalElements").asLong();
        assertThat(severityTotal).isEqualTo(actionableTotal);

        for (String type : new String[] {"VULNERABILITY", "COMPROMISE", "LIFECYCLE_DRIFT", "QUANTUM_VULNERABLE", "SBOM_QUALITY"}) {
            long leadershipCount = body.get("openFindingsByType").get(type).asLong();
            MvcResult findingsResult = mockMvc.perform(get("/findings").param("type", type).param("size", "1"))
                    .andExpect(status().isOk())
                    .andReturn();
            long findingsTotal = objectMapper.readTree(findingsResult.getResponse().getContentAsString())
                    .get("totalElements").asLong();
            assertThat(leadershipCount).isEqualTo(findingsTotal);
        }

        assertThat(body.get("kevExposure").get("kevFindingCount").asLong() - kevBefore).isEqualTo(2);
        assertThat(body.get("kevExposure").get("kevPastDueCount").asLong() - kevPastDueBefore).isEqualTo(1);
        assertThat(body.get("kevExposure").get("kevByLifecycleStage").get("DEPLOYED").asLong() - kevDeployedBefore).isEqualTo(2);

        assertThat(body.get("riskTrend").get("available").asBoolean()).isFalse();

        // Coverage: P1 staged [SOURCE, DEPLOYED] present / [BUILD, ANALYZED] missing, P2 legacy, P3 none.
        JsonNode products = body.get("sbomStageCoverage").get("products");
        JsonNode p1Row = findProductRow(products, p1.getId());
        assertThat(p1Row.get("mode").asText()).isEqualTo("STAGED");
        assertThat(toList(p1Row.get("stagesPresent"))).containsExactlyInAnyOrder("SOURCE", "DEPLOYED");
        assertThat(toList(p1Row.get("stagesMissing"))).containsExactlyInAnyOrder("BUILD", "ANALYZED");

        JsonNode p2Row = findProductRow(products, p2.getId());
        assertThat(p2Row.get("mode").asText()).isEqualTo("LEGACY");

        JsonNode p3Row = findProductRow(products, p3.getId());
        assertThat(p3Row.get("mode").asText()).isEqualTo("NONE");

        // >= rather than == : the H2 database is shared by every @SpringBootTest context in the
        // run, so a non-transactional test class elsewhere may have left other non-Unassigned
        // products behind. The three per-product assertions above already pin this test's own rows.
        assertThat(body.get("sbomStageCoverage").get("summary").get("productCount").asInt()).isGreaterThanOrEqualTo(3);

        // MTTR.
        assertThat(body.get("mttr").get("resolvedCount").asLong()).isEqualTo(2);
        assertThat(body.get("mttr").get("meanHours").asDouble()).isEqualTo(36.0);
        assertThat(body.get("mttr").get("medianHours").asDouble()).isEqualTo(36.0);

        // weeklyFlow has 12 entries.
        assertThat(body.get("weeklyFlow")).hasSize(12);

        // currentRisk.topFindingId agrees with /actionable?rankBy=SCORE's top row.
        MvcResult scoreRankedResult = mockMvc.perform(get("/actionable").param("rankBy", "SCORE").param("size", "1"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode scoreRankedBody = objectMapper.readTree(scoreRankedResult.getResponse().getContentAsString());
        if (scoreRankedBody.get("content").size() > 0) {
            String topId = scoreRankedBody.get("content").get(0).get("id").asText();
            assertThat(body.get("currentRisk").get("topFindingId").asText()).isEqualTo(topId);
        }
    }

    @Test
    void mttrWindowDaysZeroIs400() throws Exception {
        mockMvc.perform(get("/metrics/leadership").param("mttrWindowDays", "0"))
                .andExpect(status().isBadRequest());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static JsonNode findProductRow(JsonNode products, UUID productId) {
        for (JsonNode node : products) {
            if (node.get("productId").asText().equals(productId.toString())) {
                return node;
            }
        }
        throw new AssertionError("no coverage row for product " + productId);
    }

    private static java.util.List<String> toList(JsonNode array) {
        java.util.List<String> result = new java.util.ArrayList<>();
        array.forEach(n -> result.add(n.asText()));
        return result;
    }

    private Product newProduct(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.save(product);
    }

    private SBOMComponent seedSbomComponent(UUID productId, SbomLifecycleStage stage) {
        SBOMComponent component = new SBOMComponent();
        component.setName("t7-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:npm/t7-lib@1.0.0-" + UUID.randomUUID());
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(productRepository.findById(productId).orElseThrow());
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setLifecycleStage(stage);
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);
        return component;
    }

    private UUID seedAlert(SBOMComponent component, String severity, boolean kev, LocalDate kevDueDate) {
        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2099-" + Math.abs(cveCounter().hashCode() % 90000 + 10000));
        cve.setDescription("Seeded by LeadershipMetricsTest");
        cve.setBaseSeverity(severity);
        cve.setCvssScore(9.0d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(kev ? ActionableReason.KEV : ActionableReason.EPSS_HIGH);
        if (!kev) {
            alert.setEpssScore(0.5);
        }
        alert.setKevDueDate(kevDueDate);
        alert.setRiskScore(50.0);
        return alertRepository.save(alert).getId();
    }

    private void newResolvedItem(UUID productId, UUID createdById, LocalDateTime createdAt, LocalDateTime resolvedAt) {
        ActionItem item = new ActionItem();
        item.setTitle("T7 item " + UUID.randomUUID());
        item.setProductId(productId);
        item.setStatus(RemediationStatus.RESOLVED);
        item.setCreatedById(createdById);
        item.setCreatedAt(createdAt);
        item.setUpdatedAt(resolvedAt);
        item.setResolvedAt(resolvedAt);
        actionItemRepository.save(item);
    }

}
