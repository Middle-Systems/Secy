package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The read/delete surface of {@code /assets}, and the {@code assetId} filter on {@code /actionable}
 * that it shares machinery with.
 *
 * <p>Alerts are seeded with their enrichment already written, the way {@code EnrichmentService} would
 * have left them: this pins the query surface, not the funnel. The SBOM-derived alert in the seed is
 * there on purpose — it is what proves the two estates do not bleed into each other's filters.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AssetControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private AssetComponentRepository assetComponentRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    private UUID apiImageId;
    private UUID hostId;
    private UUID productId;
    private String productName;

    /** Kept from the seed so a test can point a second alert at it without a lazy re-fetch. */
    private SBOMComponent shippedComponent;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        epssRepository.deleteAll();

        Product product = new Product();
        productName = "Acme API " + UUID.randomUUID();
        product.setName(productName);
        productId = productRepository.save(product).getId();

        Vulnerability openssl = cve("CVE-2099-6001");
        Vulnerability lodash = cve("CVE-2099-6002");
        Vulnerability glibc = cve("CVE-2099-6003");
        Vulnerability shipped = cve("CVE-2099-6004");

        // Two assets: one container image linked to the product, one unlinked host.
        Asset image = asset(AssetType.CONTAINER_IMAGE, "acme/api:1.4.2", product);
        AssetComponent opensslComponent = component(image, "openssl", "3.1.3-r0", null);
        AssetComponent lodashComponent = component(image, "lodash", "4.17.20", "pkg:npm/lodash@4.17.20");
        apiImageId = assetRepository.saveAndFlush(image).getId();

        Asset host = asset(AssetType.HOST, "build-agent-07", null);
        AssetComponent glibcComponent = component(host, "glibc", "2.35", null);
        hostId = assetRepository.saveAndFlush(host).getId();

        // A product/SBOM alert for the same estate — it must never show up under an asset filter,
        // and the asset alerts must never show up under a product filter.
        SBOMComponent sbomComponent = new SBOMComponent();
        sbomComponent.setName("log4j-core");
        sbomComponent.setVersion("2.14.1");
        sbomComponent.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbomComponent.setSbom(sbom);
        sbom.getComponents().add(sbomComponent);
        sbomRepository.saveAndFlush(sbom);
        shippedComponent = sbomComponent;

        assetAlert(openssl, opensslComponent, true, AlertLifecycleState.ACTIVE);
        assetAlert(lodash, lodashComponent, true, AlertLifecycleState.ACTIVE);
        // Auto-resolved: still on record, but not work, so it must not be counted or listed.
        assetAlert(glibc, glibcComponent, true, AlertLifecycleState.AUTO_RESOLVED);

        VulnerabilityAlert productAlert = new VulnerabilityAlert();
        productAlert.setVulnerability(shipped);
        productAlert.setComponent(sbomComponent);
        enrichLikeTheServiceWould(productAlert);
        alertRepository.saveAndFlush(productAlert);
    }

    /* ------------------------------------------------------------------ */
    /* List                                                               */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void listReturnsEveryAssetWithItsComponentAndActionableCounts() throws Exception {
        mockMvc.perform(get("/assets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                // Ordered by name: acme/api:1.4.2 then build-agent-07.
                .andExpect(jsonPath("$.content[0].name").value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.content[0].type").value("CONTAINER_IMAGE"))
                .andExpect(jsonPath("$.content[0].productId").value(productId.toString()))
                .andExpect(jsonPath("$.content[0].componentCount").value(2))
                .andExpect(jsonPath("$.content[0].actionableCount").value(2))
                .andExpect(jsonPath("$.content[1].name").value("build-agent-07"))
                .andExpect(jsonPath("$.content[1].productId").doesNotExist())
                .andExpect(jsonPath("$.content[1].componentCount").value(1))
                // Its only alert is AUTO_RESOLVED, which is not work.
                .andExpect(jsonPath("$.content[1].actionableCount").value(0));
    }

    @Test
    @WithMockUser
    void listFiltersByTypeAndByProduct() throws Exception {
        mockMvc.perform(get("/assets").param("type", "HOST"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].name").value("build-agent-07"));

        mockMvc.perform(get("/assets").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].name").value("acme/api:1.4.2"));
    }

    /* ------------------------------------------------------------------ */
    /* Detail                                                             */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void detailCarriesTheAssetAndItsActionableItems() throws Exception {
        mockMvc.perform(get("/assets/{id}", apiImageId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(apiImageId.toString()))
                .andExpect(jsonPath("$.name").value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.componentCount").value(2))
                // The same rows GET /actionable returns, in the same shape and the same order.
                .andExpect(jsonPath("$.actionableItems.totalElements").value(2))
                .andExpect(jsonPath("$.actionableItems.content", hasSize(2)))
                .andExpect(jsonPath("$.actionableItems.content[0].assetId").value(apiImageId.toString()))
                .andExpect(jsonPath("$.actionableItems.content[0].assetName").value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.actionableItems.content[0].productId").doesNotExist())
                .andExpect(jsonPath("$.actionableItems.content[0].componentName").isNotEmpty());
    }

    @Test
    @WithMockUser
    void anUnknownAssetIs404() throws Exception {
        mockMvc.perform(get("/assets/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* The /actionable filter                                             */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void actionableFiltersToOneAssetAndExcludesSbomAlerts() throws Exception {
        mockMvc.perform(get("/actionable").param("assetId", apiImageId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content[0].assetName").value("acme/api:1.4.2"));

        // The host's only alert is auto-resolved, so it is on record but not on the list.
        mockMvc.perform(get("/actionable").param("assetId", hostId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    @WithMockUser
    void aProductFilterDoesNotReachAnAssetLinkedToThatProduct() throws Exception {
        // acme/api:1.4.2 IS linked to this product, and its alerts still must not appear: a product
        // filter asks what the product declares it ships, not what happens to be running.
        mockMvc.perform(get("/actionable").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-6004"))
                .andExpect(jsonPath("$.content[0].assetId").doesNotExist());
    }

    @Test
    @WithMockUser
    void theDetailViewListsBothEstatesForOneCve() throws Exception {
        // One CVE affecting an SBOM component and an asset component: the "everything this affects"
        // block has to span both, which is why its query LEFT JOINs each component FK.
        Vulnerability shared = cveRepository.findById("CVE-2099-6001").orElseThrow();

        VulnerabilityAlert alsoShipped = new VulnerabilityAlert();
        alsoShipped.setVulnerability(shared);
        alsoShipped.setComponent(shippedComponent);
        enrichLikeTheServiceWould(alsoShipped);
        UUID id = alertRepository.saveAndFlush(alsoShipped).getId();

        // Filters compare against a literal rather than testing for key presence: the DTO serializes
        // both estates' fields on every entry, so `?(@.assetId)` is true even where the value is
        // null. The sort is by alert id, which is a random UUID, so index-based assertions would be
        // flaky too.
        mockMvc.perform(get("/actionable/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.affectedComponents", hasSize(2)))
                .andExpect(jsonPath("$.affectedComponents[?(@.assetName == 'acme/api:1.4.2')]", hasSize(1)))
                .andExpect(jsonPath("$.affectedComponents[?(@.name == 'openssl')]", hasSize(1)))
                .andExpect(jsonPath("$.affectedComponents[?(@.productName == '" + productName + "')]",
                        hasSize(1)))
                .andExpect(jsonPath("$.affectedComponents[?(@.name == 'log4j-core')]", hasSize(1)));
    }

    /* ------------------------------------------------------------------ */
    /* Delete                                                             */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void deleteRemovesTheAssetItsComponentsAndItsAlertsAndSaysHowMany() throws Exception {
        mockMvc.perform(delete("/assets/{id}", apiImageId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(apiImageId.toString()))
                .andExpect(jsonPath("$.name").value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.componentsRemoved").value(2))
                .andExpect(jsonPath("$.alertsRemoved").value(2));

        assertThat(assetRepository.findById(apiImageId)).isEmpty();
        assertThat(assetComponentRepository.findAllByAssetId(apiImageId)).isEmpty();
        assertThat(alertRepository.findAllByAssetId(apiImageId)).isEmpty();

        // The other asset and the product's own alert are untouched.
        assertThat(assetRepository.findById(hostId)).isPresent();
        mockMvc.perform(get("/actionable").param("productId", productId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @WithMockUser
    void deletingAnUnknownAssetIs404() throws Exception {
        mockMvc.perform(delete("/assets/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Seeding helpers                                                    */
    /* ------------------------------------------------------------------ */

    private Asset asset(AssetType type, String name, Product product) {
        Asset asset = new Asset();
        asset.setType(type);
        asset.setName(name);
        asset.setProduct(product);
        asset.setStatus(Asset.STATUS_COMPLETED);
        asset.setScanner("Trivy");
        asset.setLastScannedAt(LocalDateTime.now().minusHours(1));
        return asset;
    }

    private static AssetComponent component(Asset asset, String name, String version, String purl) {
        AssetComponent component = new AssetComponent();
        component.setAsset(asset);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setSource(AssetComponentSource.TRIVY);
        component.setPresentInLastScan(true);
        component.setLastSeenAt(LocalDateTime.now());
        asset.getComponents().add(component);
        return component;
    }

    private Vulnerability cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded CVE " + id + " for the asset contract test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
    }

    private void assetAlert(Vulnerability cve, AssetComponent component, boolean actionable,
                            AlertLifecycleState state) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setAssetComponent(component);
        enrichLikeTheServiceWould(alert);
        alert.setActionable(actionable);
        alert.setLifecycleState(state);
        alertRepository.saveAndFlush(alert);
    }

    /** The denormalized snapshot EnrichmentService would have written. */
    private static void enrichLikeTheServiceWould(VulnerabilityAlert alert) {
        alert.setActionable(true);
        alert.setActionableReason(ActionableReason.EPSS_HIGH);
        alert.setEpssScore(0.5d);
        alert.setEpssPercentile(0.95d);
        alert.setCvssScore(7.5d);
        alert.setExploitMaturity(ExploitMaturity.NONE);
        alert.setFixState(FixState.FIXED);
        alert.setFixedVersions("9.9.9");
        alert.setFixSource(FixSource.SCANNER);
        alert.setMatchConfidence(MatchConfidence.EXACT);
        alert.setLifecycleState(AlertLifecycleState.ACTIVE);
        alert.setCreatedAt(LocalDateTime.now());
        alert.setLastSeenAt(LocalDateTime.now());
    }

}
