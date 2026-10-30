package net.jdesive.secy.vex;

import net.jdesive.secy.job.JobRunner;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexPrecedenceConfigRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexPrecedenceConfig;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M1f acceptance bar: a tenant-issued OpenVEX {@code not_affected} statement moves a KEV-driven
 * finding off the default work list, with its justification and the full statement shown on the
 * detail view — while {@code actionable}/{@code actionableReason}/{@code triageState} stay untouched.
 *
 * <p>Modeled on {@code LifecycleDriftAcceptanceTest}'s upload/{@code jobRunner.poll()}/await-terminal
 * pattern: the {@code VEX_UPLOAD} job must actually commit for its effect to be observable, so this is
 * deliberately not {@code @Transactional}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class VexAcceptanceTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);
    private static final String CVE_ID = "CVE-2099-7001";
    private static final String LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    @Autowired
    private MockMvc mockMvc;

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
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private CompromiseFindingRepository compromiseFindingRepository;

    @Autowired
    private LifecycleDriftFindingRepository lifecycleDriftFindingRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private TriageEventRepository triageEventRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @Autowired
    private VexPrecedenceConfigRepository vexPrecedenceConfigRepository;

    private UUID productId;
    private UUID alertId;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        triageEventRepository.deleteAll();
        compromiseFindingRepository.deleteAll();
        alertRepository.deleteAll();
        vexStatementRepository.deleteAll();
        vexDocumentRepository.deleteAll();
        vexPrecedenceConfigRepository.deleteAll();
        lifecycleDriftFindingRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        kevRepository.deleteAll();
        epssRepository.deleteAll();

        Product product = new Product();
        product.setName("Acme Payments");
        productId = productRepository.save(product).getId();

        alertId = seedAlert(productId, "Acme Payments", LOG4J_PURL, CVE_ID);
    }

    @AfterEach
    void resetPrecedenceConfig() {
        vexPrecedenceConfigRepository.deleteAll();
    }

    @Test
    @WithMockUser
    void aTenantNotAffectedStatementMovesTheFindingToNotAffectedWithTheJustificationShown() throws Exception {
        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(alertId.toString()))
                .andExpect(jsonPath("$.content[0].vexStatus").doesNotExist());

        uploadAndAwait("TENANT", null, body("openvex-tenant-not-affected.json"));

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(reloaded.getVexJustification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
        assertThat(reloaded.getVexStatementId()).isNotNull();
        assertThat(reloaded.isVexConflict()).isFalse();
        assertThat(reloaded.getVexUpdatedAt()).isNotNull();
        // Orthogonal — the funnel and triage are untouched by VEX.
        assertThat(reloaded.isActionable()).isTrue();
        assertThat(reloaded.getActionableReason()).isEqualTo(ActionableReason.KEV);
        assertThat(reloaded.getTriageState()).isEqualTo(TriageState.OPEN);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id == '" + alertId + "')]", org.hamcrest.Matchers.hasSize(0)));

        mockMvc.perform(get("/actionable").param("vexStatus", "NOT_AFFECTED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(alertId.toString()))
                .andExpect(jsonPath("$.content[0].vexStatus").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.content[0].vexJustification").value("VULNERABLE_CODE_NOT_IN_EXECUTE_PATH"));

        mockMvc.perform(get("/actionable/{id}", alertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vex.status").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.vex.justification").value("VULNERABLE_CODE_NOT_IN_EXECUTE_PATH"))
                .andExpect(jsonPath("$.vex.policy").value("TENANT_OVER_VENDOR"))
                .andExpect(jsonPath("$.vex.statements", org.hamcrest.Matchers.hasSize(1)))
                .andExpect(jsonPath("$.vex.statements[0].role").value("WON"))
                .andExpect(jsonPath("$.vex.statements[0].origin").value("TENANT"))
                .andExpect(jsonPath("$.vex.statements[0].format").value("OPENVEX"))
                .andExpect(jsonPath("$.vex.statements[0].author").value("Acme Product Security"))
                .andExpect(jsonPath("$.vex.statements[0].impactStatement")
                        .value("JndiLookup is stripped from the shaded jar at build time."))
                .andExpect(jsonPath("$.vex.statements[0].sourceJustification")
                        .value("vulnerable_code_not_in_execute_path"));
    }

    @Test
    @WithMockUser
    void tenantOverridesVendorByDefaultAndPolicyFlipReResolves() throws Exception {
        uploadAndAwait("VENDOR", null, cycloneDxAffected("vendor-doc-1"));
        uploadAndAwait("TENANT", null, body("openvex-tenant-not-affected.json"));

        VulnerabilityAlert afterBoth = alertRepository.findById(alertId).orElseThrow();
        assertThat(afterBoth.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(afterBoth.isVexConflict()).isFalse();

        mockMvc.perform(put("/vex/settings/precedence")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policy\": \"VENDOR_OVER_TENANT\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policy").value("VENDOR_OVER_TENANT"))
                .andExpect(jsonPath("$.alertsChanged").value(1));

        VulnerabilityAlert afterFlip = alertRepository.findById(alertId).orElseThrow();
        assertThat(afterFlip.getVexStatus()).isEqualTo(VexStatus.AFFECTED);
    }

    @Test
    @WithMockUser
    void twoTenantAuthorsDisagreeingAreFlaggedNotGuessed() throws Exception {
        uploadAndAwait("TENANT", null, openVexDoc("https://acme.example/vex/conflict-a", "Team A",
                "CVE-2099-7001", LOG4J_PURL, "not_affected", "component_not_present", null, "2026-01-01T00:00:00Z"));
        uploadAndAwait("TENANT", null, openVexDoc("https://acme.example/vex/conflict-b", "Team B",
                "CVE-2099-7001", LOG4J_PURL, "affected", null, null, "2026-01-01T00:00:00Z"));

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.isVexConflict()).isTrue();
        assertThat(reloaded.getVexStatus()).isNull();
        assertThat(reloaded.getVexStatementId()).isNull();

        // Nothing is suppressed by a conflict -- it stays on the default work list.
        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id == '" + alertId + "')]", org.hamcrest.Matchers.hasSize(1)));

        mockMvc.perform(get("/actionable/{id}", alertId))
                .andExpect(jsonPath("$.vex.conflict").value(true))
                .andExpect(jsonPath("$.vex.statements", org.hamcrest.Matchers.hasSize(2)))
                .andExpect(jsonPath("$.vex.statements[0].role").value("CONFLICTING"))
                .andExpect(jsonPath("$.vex.statements[1].role").value("CONFLICTING"));
    }

    @Test
    @WithMockUser
    void sameAuthorNewerStatementSupersedesOlder() throws Exception {
        // Deliberately earlier than the fixture file's own "last_updated" (2026-01-01), so the
        // fixture's statement is unambiguously the newer one from the same author.
        uploadAndAwait("TENANT", null, openVexDoc("https://acme.example/vex/same-author-1", "Acme Product Security",
                "CVE-2099-7001", LOG4J_PURL, "under_investigation", null, null, "2025-01-01T00:00:00Z"));
        VulnerabilityAlert afterFirst = alertRepository.findById(alertId).orElseThrow();
        assertThat(afterFirst.getVexStatus()).isEqualTo(VexStatus.UNDER_INVESTIGATION);

        uploadAndAwait("TENANT", null, body("openvex-tenant-not-affected.json"));
        VulnerabilityAlert afterSecond = alertRepository.findById(alertId).orElseThrow();
        assertThat(afterSecond.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(afterSecond.isVexConflict()).isFalse();
    }

    @Test
    @WithMockUser
    void reUploadingTheSameDocumentIdSupersedesIt() throws Exception {
        String docId = "https://acme.example/vex/reupload";
        uploadAndAwait("TENANT", null, openVexDoc(docId, "Acme Product Security",
                "CVE-2099-7001", LOG4J_PURL, "under_investigation", null, null, "2026-01-01T00:00:00Z"));
        List<VexDocument> afterFirst = vexDocumentRepository.findAll();
        assertThat(afterFirst).hasSize(1);
        UUID firstDocumentId = afterFirst.get(0).getId();

        uploadAndAwait("TENANT", null, openVexDoc(docId, "Acme Product Security",
                "CVE-2099-7001", LOG4J_PURL, "not_affected", "component_not_present", null, "2026-01-02T00:00:00Z"));

        VexDocument old = vexDocumentRepository.findById(firstDocumentId).orElseThrow();
        assertThat(old.isActive()).isFalse();
        assertThat(old.getDeactivatedAt()).isNotNull();
        assertThat(old.getSupersededById()).isNotNull();

        List<VexDocument> all = vexDocumentRepository.findAll();
        assertThat(all).hasSize(2);
        VexDocument current = all.stream().filter(d -> !d.getId().equals(firstDocumentId)).findFirst().orElseThrow();
        assertThat(current.isActive()).isTrue();

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
    }

    @Test
    @WithMockUser
    void deactivatingTheDocumentClearsTheFinding() throws Exception {
        uploadAndAwait("TENANT", null, body("openvex-tenant-not-affected.json"));
        VulnerabilityAlert afterUpload = alertRepository.findById(alertId).orElseThrow();
        assertThat(afterUpload.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);

        VexDocument document = vexDocumentRepository.findAll().get(0);
        mockMvc.perform(post("/vex/documents/{id}/deactivate", document.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        VulnerabilityAlert reloaded = alertRepository.findById(alertId).orElseThrow();
        assertThat(reloaded.getVexStatus()).isNull();
        assertThat(reloaded.isVexConflict()).isFalse();

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id == '" + alertId + "')]", org.hamcrest.Matchers.hasSize(1)));
    }

    @Test
    @WithMockUser
    void productScopedStatementDoesNotLeakToOtherProducts() throws Exception {
        Product other = new Product();
        other.setName("Acme Other");
        UUID otherProductId = productRepository.save(other).getId();
        UUID otherAlertId = seedAlert(otherProductId, "Acme Other", LOG4J_PURL, CVE_ID);

        uploadAndAwait("TENANT", productId.toString(), body("openvex-tenant-not-affected.json"));

        VulnerabilityAlert scoped = alertRepository.findById(alertId).orElseThrow();
        assertThat(scoped.getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);

        VulnerabilityAlert unaffectedByScope = alertRepository.findById(otherAlertId).orElseThrow();
        assertThat(unaffectedByScope.getVexStatus()).isNull();
    }

    /* ---------------------------------------------------------------------- */
    /* Helpers                                                                */
    /* ---------------------------------------------------------------------- */

    private UUID seedAlert(UUID product, String productName, String purl, String cveId) {
        Product p = productRepository.findById(product).orElseThrow();

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl(purl);
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(p);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);

        Vulnerability cve = cveRepository.findById(cveId).orElseGet(() -> {
            Vulnerability v = new Vulnerability();
            v.setId(cveId);
            v.setDescription("Seeded CVE for the M1f acceptance test");
            v.setBaseSeverity("CRITICAL");
            v.setCvssScore(10.0d);
            v.setPublished(LocalDateTime.now().minusDays(10));
            v.setLastModified(LocalDateTime.now().minusDays(1));
            v.setVulnStatus("Analyzed");
            Vulnerability saved = cveRepository.save(v);

            KEV kev = new KEV();
            kev.setCveId(cveId);
            kev.setName("Seeded KEV entry for " + cveId);
            kev.setVendor("apache");
            kev.setProduct("log4j");
            kev.setAdded(LocalDateTime.now().minusDays(5));
            kev.setRequiredActions("Apply updates per vendor instructions.");
            kev.setDueDate(Date.from(LocalDate.now().plusDays(14).atStartOfDay(ZoneId.systemDefault()).toInstant()));
            kev.setKnownRansomwareCampaignUse("Known");
            kevRepository.save(kev);

            return saved;
        });

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setCreatedAt(LocalDateTime.now());
        alert.setLifecycleState(AlertLifecycleState.ACTIVE);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alert.setTriageState(TriageState.OPEN);
        alert.setCvssScore(10.0d);
        return alertRepository.save(alert).getId();
    }

    private void uploadAndAwait(String origin, String productIdParam, String documentBody) throws Exception {
        var request = post("/vex")
                .param("origin", origin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(documentBody);
        if (productIdParam != null) {
            request = request.param("productId", productIdParam);
        }
        String responseBody = mockMvc.perform(request)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("VEX_UPLOAD"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
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

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("vex/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String openVexDoc(String id, String author, String cveId, String purl, String status,
                                     String justification, String impactStatement, String lastUpdated) {
        String justificationField = justification == null ? "" : ", \"justification\": \"" + justification + "\"";
        String impactField = impactStatement == null ? "" : ", \"impact_statement\": \"" + impactStatement + "\"";
        return """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "%s",
                  "author": "%s",
                  "version": 1,
                  "last_updated": "%s",
                  "statements": [
                    {
                      "vulnerability": {"name": "%s"},
                      "products": [{"@id": "%s"}],
                      "status": "%s"%s%s
                    }
                  ]
                }
                """.formatted(id, author, lastUpdated, cveId, purl, status, justificationField, impactField);
    }

    private static String cycloneDxAffected(String serialSuffix) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "serialNumber": "urn:uuid:%s",
                  "metadata": {"authors": [{"name": "Widget Vendor"}]},
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-7001",
                      "analysis": {"state": "exploitable"},
                      "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]
                    }
                  ]
                }
                """.formatted(UUID.nameUUIDFromBytes(serialSuffix.getBytes(StandardCharsets.UTF_8)));
    }

}
