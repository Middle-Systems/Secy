package net.jdesive.secy.vex;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VexDocumentRepository;
import net.jdesive.secy.persistence.VexStatementRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexDocumentStatus;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
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
 * Proves the {@code CorrelationService.reconcile} -> {@code VexResolutionService.applyTo} hook (M1f
 * design decision #1: a statement ingested before its component ever existed still applies once
 * correlation raises the alert).
 */
@SpringBootTest
@Transactional
class VexCorrelationHookTest {

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private VexDocumentRepository vexDocumentRepository;

    @Autowired
    private VexStatementRepository vexStatementRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void aStatementIngestedBeforeItsComponentExistsStillAppliesOnceCorrelationRaisesTheAlert() {
        cve("CVE-2099-7101");
        advisory("GHSA-vex-hook-1", "npm", "vexpkg", "CVE-2099-7101", "0", "2.0.0");
        seedStatement("CVE-2099-7101", "npm/vexpkg", null, VexStatus.NOT_AFFECTED, VexJustification.VULNERABLE_CODE_NOT_PRESENT);

        UUID sbomId = sbom("pkg:npm/vexpkg@1.0.0", "vexpkg", "1.0.0");
        correlate(sbomId);

        List<VulnerabilityAlert> alerts = alertsFor(sbomId);
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).getVexStatus()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(alerts.get(0).getVexJustification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_PRESENT);
        assertThat(alerts.get(0).isVexConflict()).isFalse();
        assertThat(alerts.get(0).getVexUpdatedAt()).isNotNull();
        // Orthogonal: the funnel is untouched by VEX.
        assertThat(alerts.get(0).isActionable()).isFalse();
    }

    @Test
    void zeroVexStatementsLeavesEveryAlertsSnapshotNull() {
        cve("CVE-2099-7102");
        advisory("GHSA-vex-hook-2", "npm", "novex", "CVE-2099-7102", "0", "2.0.0");

        UUID sbomId = sbom("pkg:npm/novex@1.0.0", "novex", "1.0.0");
        correlate(sbomId);

        List<VulnerabilityAlert> alerts = alertsFor(sbomId);
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).getVexStatus()).isNull();
        assertThat(alerts.get(0).isVexConflict()).isFalse();
        assertThat(alerts.get(0).getVexUpdatedAt()).isNull();
    }

    @Test
    void aVersionPinnedStatementForTheWrongVersionDoesNotApplyButAVersionlessOneDoes() {
        cve("CVE-2099-7103");
        advisory("GHSA-vex-hook-3", "npm", "pinnedpkg", "CVE-2099-7103", "0", "2.0.0");
        seedStatement("CVE-2099-7103", "npm/pinnedpkg", "9.9.9", VexStatus.NOT_AFFECTED, VexJustification.COMPONENT_NOT_PRESENT);

        UUID sbomId = sbom("pkg:npm/pinnedpkg@1.0.0", "pinnedpkg", "1.0.0");
        correlate(sbomId);

        List<VulnerabilityAlert> mismatched = alertsFor(sbomId);
        assertThat(mismatched).hasSize(1);
        assertThat(mismatched.get(0).getVexStatus()).isNull();

        // Now add a versionless statement for the same identity/CVE — it should apply to any version.
        seedStatement("CVE-2099-7103", "npm/pinnedpkg", null, VexStatus.FIXED, null);
        entityManager.flush();
        entityManager.clear();

        correlate(sbomId);
        List<VulnerabilityAlert> resolved = alertsFor(sbomId);
        assertThat(resolved).hasSize(1);
        assertThat(resolved.get(0).getVexStatus()).isEqualTo(VexStatus.FIXED);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private CorrelationService.CorrelationSummary correlate(UUID sbomId) {
        entityManager.flush();
        entityManager.clear();
        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        CorrelationService.CorrelationSummary summary = correlationService.correlate(sbom);
        entityManager.flush();
        return summary;
    }

    private List<VulnerabilityAlert> alertsFor(UUID sbomId) {
        return alertRepository.findAllBySbomIdForCorrelation(sbomId);
    }

    private void cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for a VEX correlation-hook test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);
    }

    private OsvAdvisory advisory(String osvId, String ecosystem, String packageName, String alias,
                                 String introduced, String fixed) {
        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId(osvId);
        advisory.setEcosystem(ecosystem);
        advisory.setPackageName(packageName);
        advisory.setModified(LocalDateTime.now());
        advisory.getAliases().add(alias);

        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("SEMVER");
        range.setIntroduced(introduced);
        range.setFixed(fixed);
        advisory.getRanges().add(range);

        return osvRepository.save(advisory);
    }

    private UUID sbom(String purl, String name, String version) {
        Product product = new Product();
        product.setName("vex-hook-test-" + UUID.randomUUID());
        product = productRepository.save(product);

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setSpecVersion("1.5");
        sbom.setVersion(1);
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        component.setSbom(sbom);
        sbom.getComponents().add(component);

        return sbomRepository.save(sbom).getId();
    }

    /** Seeds one active {@link VexDocument}/{@link VexStatement} pair directly, bypassing ingestion. */
    private void seedStatement(String cveId, String matchKey, String matchVersion, VexStatus status, VexJustification justification) {
        VexDocument document = new VexDocument();
        document.setTenantId(Tenant.DEFAULT_TENANT_ID);
        document.setFormat(VexDocumentFormat.OPENVEX);
        document.setDocumentKey("test:" + UUID.randomUUID());
        document.setOrigin(VexOrigin.TENANT);
        document.setStatus(VexDocumentStatus.COMPLETED);
        document.setContentSha256("deadbeef");
        document.setActive(true);
        document.setStatementCount(1);
        document.setSkippedCount(0);
        document = vexDocumentRepository.save(document);

        VexStatement statement = new VexStatement();
        statement.setTenantId(Tenant.DEFAULT_TENANT_ID);
        statement.setDocumentId(document.getId());
        statement.setFormat(VexDocumentFormat.OPENVEX);
        statement.setOrigin(VexOrigin.TENANT);
        statement.setAuthor("Test Author");
        statement.setAuthorKey("test author");
        statement.setActive(true);
        statement.setCveId(cveId);
        statement.setStatus(status);
        statement.setSourceStatus(status.name().toLowerCase());
        statement.setJustification(justification);
        statement.setProductRef(matchKey);
        statement.setTargetPurl("pkg:" + matchKey);
        statement.setMatchKey(matchKey);
        statement.setMatchVersion(matchVersion);
        statement.setStatementTimestamp(LocalDateTime.now());
        statement.setOrdinal(0);
        vexStatementRepository.save(statement);
    }

}
