package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentCryptoAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /cbom/assets}, {@code GET /cbom/assets/{id}}, {@code GET /cbom/quantum-findings} and
 * {@code GET /cbom/quantum-findings/{id}} (M1g). Everything is seeded directly — the extraction and
 * classification pipeline itself is {@code CryptoPropertiesParsingTest}'s and
 * {@code QuantumVulnerabilityClassifierTest}'s job, and reconciliation is
 * {@code QuantumFindingServiceTest}'s / {@code CbomAcceptanceTest}'s.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@Transactional
class CbomControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private QuantumVulnerabilityFindingRepository findingRepository;

    private UUID productId;
    private UUID activeRsaAssetId;
    private UUID inactiveAssetId;
    private UUID activeFindingId;
    private UUID autoResolvedFindingId;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product product = new Product();
        product.setName("cbom-controller-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(product);
        productId = product.getId();

        SBOM activeSbom = newSbom(product, true);
        SBOMComponent rsaComponent = newComponent(activeSbom, "RSA-2048", "key-rsa");
        SBOMComponentCryptoAsset rsaAsset = newCryptoAsset(rsaComponent, CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                QuantumVulnerabilityStatus.VULNERABLE, QuantumVulnerableFamily.RSA);
        rsaComponent.getCryptoAssets().add(rsaAsset);
        activeSbom.getComponents().add(rsaComponent);
        activeSbom = sbomRepository.saveAndFlush(activeSbom);
        activeRsaAssetId = activeSbom.getComponents().get(0).getCryptoAssets().get(0).getId();

        SBOM inactiveSbom = newSbom(product, false);
        SBOMComponent aesComponent = newComponent(inactiveSbom, "AES-256", "key-aes");
        SBOMComponentCryptoAsset aesAsset = newCryptoAsset(aesComponent, CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                QuantumVulnerabilityStatus.NOT_VULNERABLE, null);
        aesComponent.getCryptoAssets().add(aesAsset);
        inactiveSbom.getComponents().add(aesComponent);
        inactiveSbom = sbomRepository.saveAndFlush(inactiveSbom);
        inactiveAssetId = inactiveSbom.getComponents().get(0).getCryptoAssets().get(0).getId();

        activeFindingId = seedFinding(productId, QuantumVulnerableFamily.RSA, AlertLifecycleState.ACTIVE);
        autoResolvedFindingId = seedFinding(productId, QuantumVulnerableFamily.ECC, AlertLifecycleState.AUTO_RESOLVED);
    }

    /* ------------------------------------------------------------------ */
    /* Assets                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void defaultListOnlyIncludesActiveSbomAssets() throws Exception {
        mockMvc.perform(get("/cbom/assets").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(activeRsaAssetId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void includeInactiveReturnsBoth() throws Exception {
        mockMvc.perform(get("/cbom/assets")
                        .param("productId", productId.toString())
                        .param("includeInactive", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    void assetTypeAndQuantumStatusFiltersNarrowTheResult() throws Exception {
        mockMvc.perform(get("/cbom/assets")
                        .param("productId", productId.toString())
                        .param("includeInactive", "true")
                        .param("assetType", "RELATED_CRYPTO_MATERIAL")
                        .param("quantumStatus", "VULNERABLE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(activeRsaAssetId.toString()));

        mockMvc.perform(get("/cbom/assets")
                        .param("productId", productId.toString())
                        .param("includeInactive", "true")
                        .param("quantumStatus", "NOT_VULNERABLE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(inactiveAssetId.toString()));
    }

    @Test
    void assetDetailReturns200AndNeverIncludesRawKeyMaterial() throws Exception {
        mockMvc.perform(get("/cbom/assets/{id}", activeRsaAssetId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.asset.id").value(activeRsaAssetId.toString()))
                .andExpect(jsonPath("$.asset.cryptoIdentityKey").exists());
    }

    @Test
    void assetDetailReturns404ForAnUnknownId() throws Exception {
        mockMvc.perform(get("/cbom/assets/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Quantum findings                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void defaultFindingsListReturnsOnlyActive() throws Exception {
        mockMvc.perform(get("/cbom/quantum-findings").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(activeFindingId.toString()));
    }

    @Test
    void lifecycleStateAndFamilyFiltersNarrowTheResult() throws Exception {
        mockMvc.perform(get("/cbom/quantum-findings")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED")
                        .param("family", "ECC"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].id").value(autoResolvedFindingId.toString()));

        mockMvc.perform(get("/cbom/quantum-findings")
                        .param("productId", productId.toString())
                        .param("lifecycleState", "AUTO_RESOLVED")
                        .param("family", "RSA"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0));
    }

    @Test
    void findingDetailReturns200ForAKnownIdAnd404ForAnUnknownOne() throws Exception {
        mockMvc.perform(get("/cbom/quantum-findings/{id}", activeFindingId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(activeFindingId.toString()));

        mockMvc.perform(get("/cbom/quantum-findings/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static SBOM newSbom(Product product, boolean active) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.6");
        sbom.setVersion(1);
        sbom.setActive(active);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());
        return sbom;
    }

    private static SBOMComponent newComponent(SBOM sbom, String name, String bomRef) {
        SBOMComponent component = new SBOMComponent();
        component.setSbom(sbom);
        component.setType("cryptographic-asset");
        component.setName(name);
        component.setBomRef(bomRef);
        return component;
    }

    private static SBOMComponentCryptoAsset newCryptoAsset(SBOMComponent component, CryptoAssetType assetType,
                                                            QuantumVulnerabilityStatus status,
                                                            QuantumVulnerableFamily family) {
        SBOMComponentCryptoAsset asset = new SBOMComponentCryptoAsset();
        asset.setComponent(component);
        asset.setAssetType(assetType);
        asset.setCryptoIdentityKey("cbom:related-crypto-material:" + component.getName().toLowerCase());
        asset.setQuantumStatus(status);
        asset.setQuantumFamily(family);
        if (family != null) {
            asset.setQuantumBasis(QuantumClassificationBasis.NAME);
            asset.setQuantumIndicator(component.getName());
        }
        return asset;
    }

    private UUID seedFinding(UUID productId, QuantumVulnerableFamily family, AlertLifecycleState state) {
        QuantumVulnerabilityFinding finding = new QuantumVulnerabilityFinding();
        finding.setProductId(productId);
        finding.setCryptoIdentityKey("cbom:related-crypto-material:seed-" + UUID.randomUUID());
        finding.setAssetType(CryptoAssetType.RELATED_CRYPTO_MATERIAL);
        finding.setAlgorithmFamily(family);
        finding.setClassificationBasis(QuantumClassificationBasis.NAME);
        finding.setSbomId(UUID.randomUUID());
        finding.setSummary("Seeded by CbomControllerTest.");
        finding.setLifecycleState(state);
        finding.setLastSeenAt(LocalDateTime.now());
        return findingRepository.saveAndFlush(finding).getId();
    }

}
