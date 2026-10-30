package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.MalwareHashRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.CPEMatch;
import net.jdesive.secy.persistence.entity.CPEOperator;
import net.jdesive.secy.persistence.entity.ComponentHash;
import net.jdesive.secy.persistence.entity.CveStatus;
import net.jdesive.secy.persistence.entity.MalwareHash;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1g's false-positive fix (ROADMAP.md — "M1g — CBOM ingestion"): a {@code cryptographic-asset}
 * component must never feed CPE/OSV vulnerability correlation or malware-hash compromise detection —
 * both engines would otherwise happily match a bare crypto asset name like "aes" or "rsa" against the
 * heuristic CPE corpus, or a coincidental hash collision, producing a false-positive alert/finding on
 * something that isn't a package at all.
 *
 * <p>An otherwise-identical {@code library} component (no PURL, same name/hash) is proven to still
 * behave exactly as before — the exclusion is scoped to crypto-typed components only.
 */
@SpringBootTest
class CryptoAssetCorrelationExclusionTest {

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private CompromiseDetectionService compromiseDetectionService;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository compromiseFindingRepository;

    @Autowired
    private MalwareHashRepository malwareHashRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Test
    @Transactional
    void aNoPurlCryptographicAssetIsExcludedFromCpeCorrelationButAnOrdinaryComponentIsNot() {
        Vulnerability cve = new Vulnerability();
        cve.setId("CVE-2099-6001");
        cve.setDescription("Wildcard CPE match for a product literally named aes");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.0d);
        cve.setCveStatus(CveStatus.PUBLISHED);
        cveRepository.save(cve);

        CPEOperator operator = new CPEOperator();
        operator.setOperator("OR");
        operator.setNegate(false);
        operator.setCve(cve);
        CPEMatch match = new CPEMatch();
        match.setCriteria("cpe:2.3:a:acme:aes:*:*:*:*:*:*:*:*");
        match.setVulnerable(true);
        match.setMatchCriteriaId(UUID.randomUUID().toString());
        match.setOperator(operator);
        operator.getCpeMatches().add(match);
        cve.getCpeOperators().add(operator);
        cveRepository.save(cve);

        // A plain library component with no PURL still falls through to the CPE heuristic, as today.
        SBOM librarySbom = sbomWithComponent("library");
        correlationService.correlate(librarySbom);
        List<VulnerabilityAlert> libraryAlerts = alertRepository.findAllBySbomIdForCorrelation(librarySbom.getId());
        assertThat(libraryAlerts).as("an ordinary no-PURL component still correlates via CPE").hasSize(1);

        // An otherwise-identical cryptographic-asset component must raise nothing.
        SBOM cryptoSbom = sbomWithComponent("cryptographic-asset");
        correlationService.correlate(cryptoSbom);
        List<VulnerabilityAlert> cryptoAlerts = alertRepository.findAllBySbomIdForCorrelation(cryptoSbom.getId());
        assertThat(cryptoAlerts).as("a crypto-typed component must never feed CPE correlation").isEmpty();
    }

    @Test
    @Transactional
    void aCryptographicAssetIsExcludedFromMalwareHashDetectionButAnOrdinaryComponentIsNot() {
        String digest = "d1f8a5e5c9b1e0a1a2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d";
        MalwareHash hash = new MalwareHash();
        hash.setSha256(digest);
        hash.setSignature("TestMalware");
        hash.setReporter("test");
        hash.setFirstSeen(LocalDateTime.now().minusDays(1));
        hash.setLastSeen(LocalDateTime.now());
        hash.setConfidence(1.0d);
        malwareHashRepository.saveAndFlush(hash);

        SBOM librarySbom = sbomWithHashedComponent("library", digest);
        compromiseDetectionService.detect(librarySbom);
        List<CompromiseFinding> libraryFindings =
                compromiseFindingRepository.findAllBySbomIdForDetection(librarySbom.getId());
        assertThat(libraryFindings).as("an ordinary component with a matching digest still gets a finding")
                .hasSize(1);

        SBOM cryptoSbom = sbomWithHashedComponent("cryptographic-asset", digest);
        compromiseDetectionService.detect(cryptoSbom);
        List<CompromiseFinding> cryptoFindings =
                compromiseFindingRepository.findAllBySbomIdForDetection(cryptoSbom.getId());
        assertThat(cryptoFindings).as("a crypto-typed component must never feed hash-based detection").isEmpty();
    }

    /* ------------------------------------------------------------------ */

    private SBOM sbomWithComponent(String type) {
        Product product = new Product();
        product.setName("crypto-exclusion-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(product);

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.6");
        sbom.setVersion(1);
        sbom.setActive(true);
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        SBOMComponent component = new SBOMComponent();
        component.setName("aes");
        component.setVersion("1.0");
        component.setType(type);
        component.setSbom(sbom);
        sbom.getComponents().add(component);

        return sbomRepository.saveAndFlush(sbom);
    }

    private SBOM sbomWithHashedComponent(String type, String digest) {
        Product product = new Product();
        product.setName("crypto-hash-exclusion-" + UUID.randomUUID());
        product = productRepository.saveAndFlush(product);

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        sbom.setUploadDate(LocalDateTime.now());
        sbom.setVersion(1);
        sbom.setSpecVersion("1.6");

        SBOMComponent component = new SBOMComponent();
        component.setName("suspicious-thing");
        component.setVersion("1.0");
        component.setType(type);
        component.setSbom(sbom);
        component.getHashes().add(ComponentHash.of("SHA-256", digest));
        sbom.getComponents().add(component);

        return sbomRepository.saveAndFlush(sbom);
    }

}
