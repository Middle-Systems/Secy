package net.jdesive.secy.service.cbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link QuantumFindingService#reconcileForSbom}, driven through the real
 * {@code SBOMService.createPlaceholder}/{@code ingestDocument} path so crypto extraction and
 * classification actually run.
 *
 * <p><b>Deliberately not {@code @Transactional}</b> — same reasoning as
 * {@code LifecycleDiffServiceTest}: {@code reconcileForSbom} is {@code REQUIRES_NEW}, which would
 * suspend a test's own uncommitted transaction and see none of its fixtures under READ COMMITTED.
 * Fixtures are committed for real via the actual ingest path, and {@code @BeforeEach} cleans up.
 */
@SpringBootTest
class QuantumFindingServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private QuantumFindingService quantumFindingService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private QuantumVulnerabilityFindingRepository findingRepository;

    private Product product;

    @BeforeEach
    void seed() {
        findingRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();

        Product p = new Product();
        p.setName("quantum-finding-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(p);
    }

    @Test
    void createsAFindingForAVulnerableCryptoAsset() throws Exception {
        SBOM sbom = upload(product, cdx(true), null, null);

        quantumFindingService.reconcileForSbom(sbom.getId());

        List<QuantumVulnerabilityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(1);
        QuantumVulnerabilityFinding finding = findings.get(0);
        assertThat(finding.getCryptoIdentityKey()).isEqualTo("cbom:related-crypto-material:rsa-2048");
        assertThat(finding.getAlgorithmFamily()).isEqualTo(QuantumVulnerableFamily.RSA);
        assertThat(finding.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(finding.getProductId()).isEqualTo(product.getId());
        assertThat(finding.getScopeSbomId()).isNull();
    }

    @Test
    void runningTwiceIsIdempotentSameIdNoDuplicate() throws Exception {
        SBOM sbom = upload(product, cdx(true), null, null);

        quantumFindingService.reconcileForSbom(sbom.getId());
        List<QuantumVulnerabilityFinding> first = findingRepository.findAll();
        assertThat(first).hasSize(1);
        UUID id = first.get(0).getId();

        quantumFindingService.reconcileForSbom(sbom.getId());
        List<QuantumVulnerabilityFinding> second = findingRepository.findAll();
        assertThat(second).hasSize(1);
        assertThat(second.get(0).getId()).isEqualTo(id);
    }

    @Test
    void reUploadWithoutRsaAutoResolvesThenRevivesOnReturn() throws Exception {
        upload(product, cdx(true), null, null);
        List<QuantumVulnerabilityFinding> afterFirst = findingRepository.findAll();
        assertThat(afterFirst).hasSize(1);
        UUID findingId = afterFirst.get(0).getId();

        SBOM clean = upload(product, cdx(false), null, null);
        quantumFindingService.reconcileForSbom(clean.getId());

        QuantumVulnerabilityFinding afterClean = findingRepository.findById(findingId).orElseThrow();
        assertThat(afterClean.getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        SBOM revived = upload(product, cdx(true), null, null);
        quantumFindingService.reconcileForSbom(revived.getId());

        QuantumVulnerabilityFinding afterRevive = findingRepository.findById(findingId).orElseThrow();
        assertThat(afterRevive.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(findingRepository.findAll()).hasSize(1);
    }

    @Test
    void stagedRsaInBuildDeployedWithoutCryptoStaysActiveRepresentativeIsBuild() throws Exception {
        SBOM build = upload(product, cdx(true), SbomLifecycleStage.BUILD, null);
        quantumFindingService.reconcileForSbom(build.getId());

        SBOM deployed = upload(product, cdx(false), SbomLifecycleStage.DEPLOYED, null);
        quantumFindingService.reconcileForSbom(deployed.getId());

        List<QuantumVulnerabilityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(findings.get(0).getSbomId()).isEqualTo(build.getId());
    }

    @Test
    void rsaInBothBuildAndDeployedRepresentativeIsDeployed() throws Exception {
        SBOM build = upload(product, cdx(true), SbomLifecycleStage.BUILD, null);
        quantumFindingService.reconcileForSbom(build.getId());

        SBOM deployed = upload(product, cdx(true), SbomLifecycleStage.DEPLOYED, null);
        quantumFindingService.reconcileForSbom(deployed.getId());

        List<QuantumVulnerabilityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).getSbomId()).isEqualTo(deployed.getId());
    }

    @Test
    void bucketSbomsEachGetTheirOwnScopedFinding() throws Exception {
        Product bucket = new Product();
        bucket.setName("bucket-" + UUID.randomUUID());
        bucket.setUnassigned(true);
        bucket = productRepository.saveAndFlush(bucket);

        SBOM b1 = upload(bucket, cdx(true), null, null);
        quantumFindingService.reconcileForSbom(b1.getId());
        SBOM b2 = upload(bucket, cdx(true), null, null);
        quantumFindingService.reconcileForSbom(b2.getId());

        List<QuantumVulnerabilityFinding> findings = findingRepository.findAll();
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(QuantumVulnerabilityFinding::getScopeSbomId)
                .containsExactlyInAnyOrder(b1.getId(), b2.getId());
    }

    @Test
    void inactiveSbomIsSkipped() throws Exception {
        SBOM sbom = upload(product, cdx(true), null, null);
        SBOM fresh = sbomRepository.findById(sbom.getId()).orElseThrow();
        fresh.setActive(false);
        sbomRepository.saveAndFlush(fresh);

        var summary = quantumFindingService.reconcileForSbom(sbom.getId());
        assertThat(summary.created()).isZero();
        assertThat(summary.updated()).isZero();
    }

    @Test
    void cycloneDx15DocumentProducesNoCryptoRowsOrFindings() throws Exception {
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "cryptographic-asset", "bom-ref": "key-rsa", "name": "RSA-2048",
                      "cryptoProperties": { "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": { "type": "private-key", "size": 2048 } } }
                  ] }
                """;
        SBOM sbom = upload(product, json, null, null);
        quantumFindingService.reconcileForSbom(sbom.getId());

        assertThat(findingRepository.findAll()).isEmpty();
    }

    /* ------------------------------------------------------------------ */

    private SBOM upload(Product targetProduct, String json, SbomLifecycleStage stage, String productVersion)
            throws Exception {
        NormalizedSbom document = sbomParser.parse(mapper.readTree(json));
        SBOM placeholder = sbomService.createPlaceholder(targetProduct, document,
                productVersion == null ? "1.0.0" : productVersion, json, null, null, null, stage);
        sbomService.ingestDocument(placeholder, document, JobProgress.NOOP);
        return sbomRepository.findById(placeholder.getId()).orElseThrow();
    }

    private static String cdx(boolean includeRsa) {
        String rsaComponent = includeRsa ? """
                ,
                    { "type": "cryptographic-asset", "bom-ref": "key-rsa", "name": "RSA-2048",
                      "cryptoProperties": { "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": { "type": "private-key", "size": 2048 } } }
                """ : "";
        return """
                { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                  "components": [
                    { "type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21" }
                    %s
                  ] }
                """.formatted(rsaComponent);
    }

}
