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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /findings}, {@code /findings/types} and {@code /findings/{type}/{id}} — the M1j
 * read-model union over the five finding tables. Seeds each type directly (bypassing the real
 * reconcile services, exactly like {@code ActionableTriageControllerTest}), since this endpoint only
 * reads whatever is already in those tables.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FindingControllerTest {

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
    private LifecycleDriftFindingRepository driftRepository;

    @Autowired
    private QuantumVulnerabilityFindingRepository quantumRepository;

    @Autowired
    private SbomQualityFindingRepository qualityRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    private String token;
    private UUID productId;

    private UUID vulnId1;
    private UUID vulnId2;
    private UUID vulnNotAffectedId;
    private UUID compromise1;
    private UUID compromise2;
    private UUID drift1;
    private UUID drift2;
    private UUID quantumId;
    private UUID qualityId;

    @BeforeEach
    void seed() throws Exception {
        qualityRepository.deleteAll();
        quantumRepository.deleteAll();
        driftRepository.deleteAll();
        compromiseRepository.deleteAll();
        alertRepository.deleteAll();
        userRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();

        token = registerAndLogin("finding-tester@example.com", "correct-horse-battery", "Finding Tester");

        Product product = new Product();
        product.setName("Acme Findings " + UUID.randomUUID());
        productId = productRepository.save(product).getId();

        SBOMComponent component = new SBOMComponent();
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setType("library");

        SBOM sbom = new SBOM();
        sbom.setProduct(productRepository.findById(productId).orElseThrow());
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        component.setSbom(sbom);
        sbom.getComponents().add(component);
        sbomRepository.save(sbom);

        // Vulnerability: two actionable, one non-actionable (must not appear).
        vulnId1 = seedAlert(component, "CVE-2099-0001", true, null, null);
        vulnId2 = seedAlert(component, "CVE-2099-0002", true, null, null);
        seedAlert(component, "CVE-2099-0003", false, null, null);
        vulnNotAffectedId = seedAlert(component, "CVE-2099-0004", true, VexStatus.NOT_AFFECTED, VexJustification.COMPONENT_NOT_PRESENT);
        UUID autoResolvedVulnId = seedAlert(component, "CVE-2099-0005", true, null, null);
        alertRepository.findById(autoResolvedVulnId).ifPresent(a -> {
            a.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            alertRepository.save(a);
        });

        // Compromise: two active, one auto-resolved, one ACKNOWLEDGED (triage).
        compromise1 = seedCompromise(component, "MAL-2099-0001", TriageState.OPEN);
        compromise2 = seedCompromise(component, "MAL-2099-0002", TriageState.ACKNOWLEDGED);
        UUID autoResolvedCompromise = seedCompromise(component, "MAL-2099-0003", TriageState.OPEN);
        compromiseRepository.findById(autoResolvedCompromise).ifPresent(c -> {
            c.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            compromiseRepository.save(c);
        });

        // Lifecycle drift: two active, one auto-resolved.
        drift1 = seedDrift("npm/acme-utils-1");
        drift2 = seedDrift("npm/acme-utils-2");
        UUID autoResolvedDrift = seedDrift("npm/acme-utils-3");
        driftRepository.findById(autoResolvedDrift).ifPresent(f -> {
            f.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            driftRepository.save(f);
        });

        // Quantum: one active, one auto-resolved.
        quantumId = seedQuantum("crypto/rsa-key-1");
        UUID autoResolvedQuantum = seedQuantum("crypto/rsa-key-2");
        quantumRepository.findById(autoResolvedQuantum).ifPresent(f -> {
            f.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            quantumRepository.save(f);
        });

        // SBOM quality: one active, one auto-resolved.
        qualityId = seedQuality(SbomLifecycleStage.SOURCE);
        UUID autoResolvedQuality = seedQuality(SbomLifecycleStage.BUILD);
        qualityRepository.findById(autoResolvedQuality).ifPresent(f -> {
            f.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            qualityRepository.save(f);
        });
    }

    /* ------------------------------------------------------------------ */
    /* GET /findings — tiering, paging, totals                            */
    /* ------------------------------------------------------------------ */

    @Test
    void listOrdersByTierAndStraddlesPages() throws Exception {
        // Active population: 2 compromise, 2 vulnerability (actionable) + 1 VEX-not-affected vuln
        // (still ACTIVE, still shown -- unlike /actionable), 2 drift, 1 quantum, 1 quality = 9.
        MvcResult page0 = mockMvc.perform(get("/findings").param("size", "3")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(9))
                .andExpect(jsonPath("$.content", hasSize(3)))
                .andExpect(jsonPath("$.content[0].type").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[1].type").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[2].type").value("VULNERABILITY"))
                .andReturn();
        assertThat(page0).isNotNull();

        // Page straddling the vulnerability/drift/quantum boundaries: offset 4 of 9
        // (2 compromise, 3 vulnerability, 2 drift, 1 quantum, 1 quality) lands one vulnerability row
        // in, then spans both drift rows, then the quantum row.
        mockMvc.perform(get("/findings").param("size", "4").param("page", "1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(4)))
                .andExpect(jsonPath("$.content[0].type").value("VULNERABILITY"))
                .andExpect(jsonPath("$.content[1].type").value("LIFECYCLE_DRIFT"))
                .andExpect(jsonPath("$.content[2].type").value("LIFECYCLE_DRIFT"))
                .andExpect(jsonPath("$.content[3].type").value("QUANTUM_VULNERABLE"));
    }

    @Test
    void typeFilterRestrictsToOneArm() throws Exception {
        mockMvc.perform(get("/findings").param("type", "COMPROMISE")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));

        mockMvc.perform(get("/findings").param("type", "VULNERABILITY")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3));

        mockMvc.perform(get("/findings").param("type", "LIFECYCLE_DRIFT")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));

        mockMvc.perform(get("/findings").param("type", "QUANTUM_VULNERABLE")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));

        mockMvc.perform(get("/findings").param("type", "SBOM_QUALITY")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void provenanceTypeAlwaysReturnsAnEmptyPage() throws Exception {
        mockMvc.perform(get("/findings").param("type", "PROVENANCE")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.content", hasSize(0)));
    }

    @Test
    void productIdScopesEveryArm() throws Exception {
        mockMvc.perform(get("/findings").param("productId", productId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(9));

        mockMvc.perform(get("/findings").param("productId", UUID.randomUUID().toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void assetIdExcludesThePlainProductIdTypesEntirely() throws Exception {
        // No AssetComponent fixture exists, so vulnerability/compromise arms contribute nothing
        // either -- the point pinned here is that drift/quantum/quality never even get queried.
        mockMvc.perform(get("/findings").param("assetId", UUID.randomUUID().toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void includeResolvedAddsAutoResolvedRowsWithLifecycleBasis() throws Exception {
        mockMvc.perform(get("/findings").param("includeResolved", "true").param("size", "50")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(14))
                .andExpect(jsonPath("$.content[?(@.lifecycleState == 'AUTO_RESOLVED')]", hasSize(5)))
                .andExpect(jsonPath("$.content[?(@.lifecycleState == 'AUTO_RESOLVED' && @.status == 'RESOLVED' "
                        + "&& @.statusBasis == 'LIFECYCLE')]", hasSize(5)));
    }

    @Test
    void linkedFilterDefaultsToUnlinkedForEverything() throws Exception {
        mockMvc.perform(get("/findings").param("linked", "false").param("size", "50")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(9));

        mockMvc.perform(get("/findings").param("linked", "true")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    /* ------------------------------------------------------------------ */
    /* Derived status                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void vexNotAffectedVulnerabilityShowsNotAffectedWithJustification() throws Exception {
        mockMvc.perform(get("/findings/{type}/{id}", "VULNERABILITY", vulnNotAffectedId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("NOT_AFFECTED"))
                .andExpect(jsonPath("$.statusBasis").value("VEX"))
                .andExpect(jsonPath("$.vexJustification").value("COMPONENT_NOT_PRESENT"))
                .andExpect(jsonPath("$.detailPath").value("/actionable/" + vulnNotAffectedId));
    }

    @Test
    void acknowledgedCompromiseShowsInProgressWithTriageBasis() throws Exception {
        mockMvc.perform(get("/findings/{type}/{id}", "COMPROMISE", compromise2)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.statusBasis").value("TRIAGE"))
                .andExpect(jsonPath("$.detailPath").value("/compromise/" + compromise2));
    }

    /* ------------------------------------------------------------------ */
    /* Per-type detail + detailPath                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void everyTypeHasADetailWithItsOwnDetailPath() throws Exception {
        mockMvc.perform(get("/findings/{type}/{id}", "VULNERABILITY", vulnId1)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detailPath").value("/actionable/" + vulnId1));

        mockMvc.perform(get("/findings/{type}/{id}", "COMPROMISE", compromise1)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detailPath").value("/compromise/" + compromise1));

        mockMvc.perform(get("/findings/{type}/{id}", "LIFECYCLE_DRIFT", drift1)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detailPath").value("/lifecycle-drift/" + drift1))
                .andExpect(jsonPath("$.productId").value(productId.toString()));

        mockMvc.perform(get("/findings/{type}/{id}", "QUANTUM_VULNERABLE", quantumId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detailPath").value("/cbom/quantum-findings/" + quantumId));

        mockMvc.perform(get("/findings/{type}/{id}", "SBOM_QUALITY", qualityId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detailPath").value("/sbom-quality/" + qualityId));
    }

    @Test
    void unknownIdIs404() throws Exception {
        mockMvc.perform(get("/findings/{type}/{id}", "VULNERABILITY", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    @Test
    void provenanceDetailAlways404s() throws Exception {
        mockMvc.perform(get("/findings/{type}/{id}", "PROVENANCE", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* GET /findings/types                                                */
    /* ------------------------------------------------------------------ */

    @Test
    void typesListsSixValuesWithProvenanceUnavailable() throws Exception {
        MvcResult result = mockMvc.perform(get("/findings/types")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(6)))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        Set<String> seen = new HashSet<>();
        boolean provenanceUnavailable = false;
        for (JsonNode node : body) {
            seen.add(node.get("type").asText());
            if ("PROVENANCE".equals(node.get("type").asText())) {
                provenanceUnavailable = !node.get("available").asBoolean();
                assertThat(node.get("note").asText()).contains("M4");
            } else {
                assertThat(node.get("available").asBoolean()).isTrue();
            }
        }
        assertThat(seen).containsExactlyInAnyOrder(
                "VULNERABILITY", "COMPROMISE", "LIFECYCLE_DRIFT", "QUANTUM_VULNERABLE", "SBOM_QUALITY", "PROVENANCE");
        assertThat(provenanceUnavailable).isTrue();
    }

    /* ------------------------------------------------------------------ */
    /* Seeding helpers                                                    */
    /* ------------------------------------------------------------------ */

    private UUID seedAlert(SBOMComponent component, String cveId, boolean actionable,
                            VexStatus vexStatus, VexJustification vexJustification) {
        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded by FindingControllerTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(actionable);
        alert.setActionableReason(actionable ? ActionableReason.KEV : null);
        alert.setVexStatus(vexStatus);
        alert.setVexJustification(vexJustification);
        return alertRepository.save(alert).getId();
    }

    private UUID seedCompromise(SBOMComponent component, String iocId, TriageState triageState) {
        CompromiseFinding finding = new CompromiseFinding();
        finding.setComponent(component);
        finding.setType(CompromiseType.MALICIOUS_PACKAGE);
        finding.setConfidence(CompromiseConfidence.CONFIRMED);
        finding.setSource("OpenSSF Malicious Packages");
        finding.setIocId(iocId);
        finding.setMatchedOn("pkg:npm/evil-pkg@1.0.0");
        finding.setSummary("Malicious code in evil-pkg (npm)");
        finding.setTriageState(triageState);
        return compromiseRepository.save(finding).getId();
    }

    private UUID seedDrift(String identityKey) {
        LifecycleDriftFinding f = new LifecycleDriftFinding();
        f.setProductId(productId);
        f.setStagePair(LifecycleStagePair.SOURCE_BUILD);
        f.setDriftKind(LifecycleDriftKind.UNEXPECTED_COMPONENT);
        f.setIdentityKey(identityKey);
        f.setComponentName("acme-internal-utils");
        f.setComponentPurl("pkg:npm/acme-internal-utils@1.0.0");
        f.setObservedVersion("1.0.0");
        f.setBaselineSbomId(UUID.randomUUID());
        f.setObservedSbomId(UUID.randomUUID());
        f.setSummary("Unexpected component " + identityKey);
        return driftRepository.save(f).getId();
    }

    private UUID seedQuantum(String cryptoIdentityKey) {
        QuantumVulnerabilityFinding f = new QuantumVulnerabilityFinding();
        f.setProductId(productId);
        f.setCryptoIdentityKey(cryptoIdentityKey);
        f.setAssetType(CryptoAssetType.ALGORITHM);
        f.setAlgorithmFamily(QuantumVulnerableFamily.RSA);
        f.setClassificationBasis(QuantumClassificationBasis.OID);
        f.setComponentName("rsa-signing-key");
        f.setSbomId(UUID.randomUUID());
        f.setSummary("RSA key vulnerable to Shor's algorithm");
        return quantumRepository.save(f).getId();
    }

    private UUID seedQuality(SbomLifecycleStage stage) {
        SbomQualityFinding f = new SbomQualityFinding();
        f.setProductId(productId);
        f.setLifecycleStage(stage);
        f.setSbomId(UUID.randomUUID());
        SbomQualityScore quality = new SbomQualityScore();
        quality.setScore(42);
        f.setQuality(quality);
        f.setScoreThreshold(70);
        f.setMissingElements("SUPPLIER,AUTHOR");
        f.setSummary("Low-quality SBOM for slot " + stage);
        return qualityRepository.save(f).getId();
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
