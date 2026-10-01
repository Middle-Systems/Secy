package net.jdesive.secy.actionitem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M1k's T4 — <b>THIS PINS THE MILESTONE'S ACCEPTANCE CRITERION</b>: "a software engineer mapped to
 * one product sees only that product's action items", met at the VIEW level via
 * {@code GET /action-items?ownedBy=me} — see ROADMAP.md's M1k section 1. Also proves, by naming it
 * explicitly, that {@code GET /action-items} with no {@code ownedBy} stays unrestricted: real
 * enforcement is Tenancy hardening's job, not M1k's.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SoftwareEngineerViewAcceptanceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private CompromiseFindingRepository compromiseRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private AppUserRepository userRepository;

    @Test
    void engineerSeesOnlyTheirOwnedProductsActionItems() throws Exception {
        String adminToken = registerAndLogin("t4-admin@example.com", "correct-horse-battery", "T4 Admin");
        // Promoted directly rather than relying on M0's "first registered = ADMIN" bootstrap rule --
        // the H2 database is shared by every @SpringBootTest context in the run, and a
        // non-transactional test class elsewhere may have already left a committed account behind.
        promoteToAdmin("t4-admin@example.com");
        String engineerToken = registerAndLogin("t4-engineer@example.com", "correct-horse-battery", "T4 Engineer");
        String thirdToken = registerAndLogin("t4-third@example.com", "correct-horse-battery", "T4 Third");
        String engineerId = userIdByEmail(adminToken, "t4-engineer@example.com");
        String thirdId = userIdByEmail(adminToken, "t4-third@example.com");

        Product productA = newProduct("T4 Product A " + UUID.randomUUID());
        Product productB = newProduct("T4 Product B " + UUID.randomUUID());

        SBOMComponent componentA = seedComponent(productA.getId());
        SBOMComponent componentB = seedComponent(productB.getId());

        UUID vulnA = seedAlert(componentA, "CVE-2099-4001");
        UUID compromiseA = seedCompromise(componentA, "MAL-2099-4001");
        UUID vulnB = seedAlert(componentB, "CVE-2099-4002");

        AssetComponent assetComponent = seedAssetComponent();
        UUID vulnAsset = seedAssetAlert(assetComponent, "CVE-2099-4003");

        // admin PATCHes engineer's roles to [SOFTWARE_ENGINEER]
        mockMvc.perform(patch("/tenant/members/" + engineerId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("roles", List.of("SOFTWARE_ENGINEER")))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/me/access").header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.views", org.hamcrest.Matchers.contains("SOFTWARE_ENGINEER")));

        UUID itemA = createItem(adminToken, "Item A", "VULNERABILITY", vulnA);
        attachFinding(adminToken, itemA, "COMPROMISE", compromiseA);
        UUID itemB = createItem(adminToken, "Item B", "VULNERABILITY", vulnB);
        UUID itemAsset = createItem(adminToken, "Item Asset", "VULNERABILITY", vulnAsset);

        // admin adds a USER owner for the engineer on product A
        mockMvc.perform(post("/products/" + productA.getId() + "/owners")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("ownerType", "USER", "userId", engineerId))))
                .andExpect(status().isCreated());

        // a TEAM link on B naming the engineer's email as free text -- never resolves to a user.
        MvcResult teamLinkResult = mockMvc.perform(post("/products/" + productB.getId() + "/owners")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerType", "TEAM", "principal", "t4-engineer@example.com"))))
                .andExpect(status().isCreated())
                .andReturn();

        // engineer: ownedBy=me returns only itemA
        mockMvc.perform(get("/action-items").param("ownedBy", "me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(itemA.toString()));

        // no ownedBy param -- unrestricted (M1k ships no enforcement)
        mockMvc.perform(get("/action-items").header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3));

        // ownedBy=me plus productId=B -- 0 (intersects, doesn't union)
        mockMvc.perform(get("/action-items").param("ownedBy", "me").param("productId", productB.getId().toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        // ownedBy=me plus status=RESOLVED -- honors status (itemA is OPEN, not RESOLVED)
        mockMvc.perform(get("/action-items").param("ownedBy", "me").param("status", "RESOLVED")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        // GET /findings?ownedBy=me -- only product A's findings (vuln + compromise), no asset rows
        MvcResult findingsResult = mockMvc.perform(get("/findings").param("ownedBy", "me").param("size", "50")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode findingsBody = objectMapper.readTree(findingsResult.getResponse().getContentAsString());
        List<String> findingIds = new java.util.ArrayList<>();
        findingsBody.get("content").forEach(n -> findingIds.add(n.get("id").asText()));
        assertThat(findingIds).containsExactlyInAnyOrder(vulnA.toString(), compromiseA.toString());

        // admin calling ownedBy=<engineerId> gets the same result as the engineer's own "me"
        mockMvc.perform(get("/action-items").param("ownedBy", engineerId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(itemA.toString()));

        // a third user owning nothing gets 0, not 3
        mockMvc.perform(get("/action-items").param("ownedBy", "me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + thirdToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        // deleting the engineer's owner link on A leaves their list empty
        MvcResult ownersResult = mockMvc.perform(get("/products/" + productA.getId() + "/owners")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andReturn();
        JsonNode owners = objectMapper.readTree(ownersResult.getResponse().getContentAsString());
        String ownerLinkId = owners.get(0).get("id").asText();
        mockMvc.perform(delete("/products/" + productA.getId() + "/owners/" + ownerLinkId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/action-items").param("ownedBy", "me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        // ownedBy=garbage -> 400
        mockMvc.perform(get("/action-items").param("ownedBy", "garbage")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isBadRequest());

        // ownedBy=me under @WithMockUser -> 401 -- see ownedByMeUnderWithMockUserIs401() below,
        // a separate @Test method since @WithMockUser only applies to JUnit-invoked test methods.

        // engineer PATCHing itemA to IN_PROGRESS then RESOLVED -> 200 both times, detail carries fix
        mockMvc.perform(patch("/action-items/" + itemA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken)
                        .content(objectMapper.writeValueAsString(Map.of("status", "IN_PROGRESS"))))
                .andExpect(status().isOk());
        mockMvc.perform(patch("/action-items/" + itemA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken)
                        .content(objectMapper.writeValueAsString(Map.of("status", "RESOLVED"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/action-items/" + itemA).header(HttpHeaders.AUTHORIZATION, "Bearer " + engineerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findings[0].fix").exists());
    }

    @Test
    @WithMockUser
    void ownedByMeUnderWithMockUserIs401() throws Exception {
        mockMvc.perform(get("/action-items").param("ownedBy", "me")).andExpect(status().isUnauthorized());
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
        component.setName("t4-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:npm/t4-lib@1.0.0-" + UUID.randomUUID());
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

    private UUID seedAlert(SBOMComponent component, String cveId) {
        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded by SoftwareEngineerViewAcceptanceTest");
        cve.setBaseSeverity("CRITICAL");
        cve.setCvssScore(9.8d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alert.setRiskScore(80.0);
        return alertRepository.save(alert).getId();
    }

    private AssetComponent seedAssetComponent() {
        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName("t4-asset:" + UUID.randomUUID());
        AssetComponent assetComponent = new AssetComponent();
        assetComponent.setName("asset-lib");
        assetComponent.setVersion("1.0.0");
        assetComponent.setPurl("pkg:npm/asset-lib@1.0.0-" + UUID.randomUUID());
        assetComponent.setAsset(asset);
        asset.getComponents().add(assetComponent);
        assetRepository.saveAndFlush(asset);
        return assetComponent;
    }

    private UUID seedAssetAlert(AssetComponent assetComponent, String cveId) {
        Vulnerability cve = new Vulnerability();
        cve.setId(cveId);
        cve.setDescription("Seeded asset alert");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(8.0d);
        cve = cveRepository.save(cve);

        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setAssetComponent(assetComponent);
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.KEV);
        alert.setRiskScore(70.0);
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
        finding.setSummary("Seeded malicious package");
        return compromiseRepository.save(finding).getId();
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

    private void attachFinding(String token, UUID itemId, String findingType, UUID findingId) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "findings", List.of(Map.of("type", findingType, "id", findingId.toString()))));
        mockMvc.perform(post("/action-items/" + itemId + "/findings")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());
    }

    private String userIdByEmail(String token, String email) throws Exception {
        MvcResult result = mockMvc.perform(get("/tenant/members").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        for (JsonNode node : body) {
            if (node.get("email").asText().equalsIgnoreCase(email)) {
                return node.get("userId").asText();
            }
        }
        throw new AssertionError("no member found with email " + email);
    }

    private void promoteToAdmin(String email) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.setRole(Role.ADMIN);
        userRepository.save(user);
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
