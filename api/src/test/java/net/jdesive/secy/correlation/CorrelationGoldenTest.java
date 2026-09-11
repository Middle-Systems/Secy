package net.jdesive.secy.correlation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.cyclonedx.CycloneDXComponent;
import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The correlation golden set: hand-built fixtures with hand-verified expected output.
 *
 * <h2>What the bar is, and why it is 1.0</h2>
 *
 * <p><b>Precision and recall must both be exactly 1.0 on every fixture.</b> These are not sampled
 * real-world SBOMs where some irreducible error rate is the honest target — every component, every
 * advisory and every CPE row in {@code src/test/resources/correlation/} was written by hand with a
 * known right answer. Anything less than a perfect score means the engine disagrees with an answer a
 * human wrote down, and that is a bug, not noise. Each fixture carries its own
 * {@code precisionBar} / {@code recallBar} so a future fixture built from real data can set a softer
 * bar without weakening these.
 *
 * <p>Precision and recall are computed over alert <em>rows</em>, not over the distinct
 * {@code (CVE, component)} pairs, and the row count is asserted separately. That is deliberate: a
 * duplicated row is invisible to a set-based score and is exactly the failure the upsert contract
 * forbids.
 *
 * <h2>Fixture layout</h2>
 *
 * <p>One directory per case under {@code src/test/resources/correlation/}, discovered automatically
 * — adding a directory adds a case, with no edit here.
 *
 * <pre>
 * correlation/NN-short-name/
 *   sbom.json        a real CycloneDX 1.5 document; its components[] are what gets correlated
 *   seed.json        { cves: [...], osv: [...], cpe: [...] }  — the world the engine sees
 *   expected.json    { description, precisionBar, recallBar, alerts: [...] }
 *   seed-2.json      optional: a second phase. The OSV mirror and the CPE rows are rebuilt from it
 *   expected-2.json  and the SAME SBOM is correlated again — this is how re-scan behaviour is tested
 *   seed-3.json      … and so on, for as many phases as the case needs
 * </pre>
 *
 * <p>Each expected alert is {@code {cveId, component, fixState, fixedVersions, fixSource,
 * matchConfidence, actionable, lifecycleState}}. Every field is asserted; {@code fixedVersions} is
 * asserted as null when the fixture says null.
 */
@SpringBootTest
@Transactional
class CorrelationGoldenTest {

    private static final String FIXTURE_ROOT = "correlation";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CorrelationService correlationService;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /* ------------------------------------------------------------------ */
    /* The suite                                                          */
    /* ------------------------------------------------------------------ */

    static Stream<String> fixtures() throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver()
                .getResources("classpath*:" + FIXTURE_ROOT + "/*/sbom.json");
        List<String> cases = new ArrayList<>();
        for (Resource resource : resources) {
            // .../correlation/<case>/sbom.json
            String[] parts = resource.getURL().getPath().split("/");
            cases.add(parts[parts.length - 2]);
        }
        cases.sort(Comparator.naturalOrder());
        return cases.stream();
    }

    @Test
    void theGoldenSetIsNotEmpty() throws IOException {
        // A misconfigured resource path would silently turn every assertion below into a no-op.
        assertThat(fixtures().toList()).hasSizeGreaterThanOrEqualTo(4);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fixtures")
    void correlationMatchesTheHandVerifiedExpectation(String fixture) throws IOException {
        UUID sbomId = createSbom(fixture);

        int phase = 1;
        while (true) {
            Optional<JsonNode> seed = readOptional(fixture, seedFile(phase));
            Optional<JsonNode> expected = readOptional(fixture, expectedFile(phase));
            if (seed.isEmpty() || expected.isEmpty()) {
                break;
            }

            applySeed(seed.get());
            entityManager.flush();
            entityManager.clear();

            SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
            correlationService.correlate(sbom);
            entityManager.flush();

            assertPhase(fixture, phase, expected.get(), sbomId);
            phase++;
        }

        assertThat(phase).as("%s ran at least one phase", fixture).isGreaterThan(1);
    }

    /* ------------------------------------------------------------------ */
    /* Assertions                                                         */
    /* ------------------------------------------------------------------ */

    private void assertPhase(String fixture, int phase, JsonNode expected, UUID sbomId) {
        String where = fixture + " phase " + phase + " — " + expected.path("description").asText();

        List<ExpectedAlert> want = new ArrayList<>();
        for (JsonNode node : expected.path("alerts")) {
            want.add(ExpectedAlert.from(node));
        }

        List<VulnerabilityAlert> got = alertRepository.findAllBySbomIdForCorrelation(sbomId).stream()
                .sorted(Comparator.comparing((VulnerabilityAlert a) -> a.getVulnerability().getId())
                        .thenComparing(a -> a.getComponent().getName()))
                .toList();

        Set<String> wantKeys = want.stream().map(ExpectedAlert::key).collect(Collectors.toCollection(LinkedHashSet::new));
        List<String> gotKeys = got.stream().map(CorrelationGoldenTest::keyOf).toList();

        long truePositives = gotKeys.stream().filter(wantKeys::contains).count();
        double precision = gotKeys.isEmpty() ? 1.0d : (double) truePositives / gotKeys.size();
        double recall = wantKeys.isEmpty() ? 1.0d
                : (double) wantKeys.stream().filter(gotKeys::contains).count() / wantKeys.size();

        assertThat(precision)
                .as("%s: precision — reported %s, expected %s", where, gotKeys, wantKeys)
                .isGreaterThanOrEqualTo(expected.path("precisionBar").asDouble(1.0d));
        assertThat(recall)
                .as("%s: recall — reported %s, expected %s", where, gotKeys, wantKeys)
                .isGreaterThanOrEqualTo(expected.path("recallBar").asDouble(1.0d));

        // Row count, separately from the score: a duplicated (component, CVE) row scores a perfect
        // precision and is exactly what the upsert contract forbids.
        assertThat(got)
                .as("%s: alert row count — reported %s", where, gotKeys)
                .hasSameSizeAs(want);

        for (ExpectedAlert wanted : want) {
            VulnerabilityAlert actual = got.stream()
                    .filter(a -> keyOf(a).equals(wanted.key()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError(where + ": no alert for " + wanted.key()));

            assertThat(actual.getFixState()).as("%s: %s fixState", where, wanted.key()).isEqualTo(wanted.fixState());
            assertThat(actual.getFixedVersions()).as("%s: %s fixedVersions", where, wanted.key()).isEqualTo(wanted.fixedVersions());
            assertThat(actual.getFixSource()).as("%s: %s fixSource", where, wanted.key()).isEqualTo(wanted.fixSource());
            assertThat(actual.getMatchConfidence()).as("%s: %s matchConfidence", where, wanted.key()).isEqualTo(wanted.matchConfidence());
            assertThat(actual.isActionable()).as("%s: %s actionable", where, wanted.key()).isEqualTo(wanted.actionable());
            assertThat(actual.getLifecycleState()).as("%s: %s lifecycleState", where, wanted.key()).isEqualTo(wanted.lifecycleState());
        }
    }

    private static String keyOf(VulnerabilityAlert alert) {
        return alert.getVulnerability().getId() + "@" + alert.getComponent().getName();
    }

    private record ExpectedAlert(String cveId, String component, FixState fixState, String fixedVersions,
                                 FixSource fixSource, MatchConfidence matchConfidence, boolean actionable,
                                 AlertLifecycleState lifecycleState) {

        static ExpectedAlert from(JsonNode node) {
            return new ExpectedAlert(
                    node.path("cveId").asText(),
                    node.path("component").asText(),
                    FixState.valueOf(node.path("fixState").asText()),
                    node.path("fixedVersions").isNull() || node.path("fixedVersions").isMissingNode()
                            ? null : node.path("fixedVersions").asText(),
                    FixSource.valueOf(node.path("fixSource").asText()),
                    MatchConfidence.valueOf(node.path("matchConfidence").asText()),
                    node.path("actionable").asBoolean(true),
                    AlertLifecycleState.valueOf(node.path("lifecycleState").asText("ACTIVE")));
        }

        String key() {
            return cveId + "@" + component;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Fixture loading                                                    */
    /* ------------------------------------------------------------------ */

    private static String seedFile(int phase) {
        return phase == 1 ? "seed.json" : "seed-" + phase + ".json";
    }

    private static String expectedFile(int phase) {
        return phase == 1 ? "expected.json" : "expected-" + phase + ".json";
    }

    private Optional<JsonNode> readOptional(String fixture, String name) throws IOException {
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream(FIXTURE_ROOT + "/" + fixture + "/" + name)) {
            return in == null ? Optional.empty() : Optional.of(mapper.readTree(in));
        }
    }

    /** Build the SBOM from the fixture's real CycloneDX document. */
    private UUID createSbom(String fixture) throws IOException {
        CycloneDXFile file;
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream(FIXTURE_ROOT + "/" + fixture + "/sbom.json")) {
            assertThat(in).as("%s/sbom.json", fixture).isNotNull();
            file = mapper.readValue(in, CycloneDXFile.class);
        }

        Product product = new Product();
        product.setName("golden-" + fixture);
        product = productRepository.save(product);

        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat(file.getBomFormat());
        sbom.setSpecVersion(file.getSpecVersion());
        sbom.setVersion(file.getVersion());
        sbom.setProductVersion("1.0.0");
        sbom.setActive(true);
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        for (CycloneDXComponent cdx : file.getComponents()) {
            SBOMComponent component = new SBOMComponent();
            component.setName(cdx.getName());
            component.setVersion(cdx.getVersion());
            component.setPurl(cdx.getPurl());
            component.setType(cdx.getType());
            component.setBomRef(cdx.getBomRef());
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }

        return sbomRepository.saveAndFlush(sbom).getId();
    }

    /**
     * Rebuild the world the engine sees: CVEs (with their KEV/EPSS rows), the OSV mirror, and the
     * NVD CPE rows.
     *
     * <p>The OSV mirror and each seeded CVE's CPE rows are cleared first, so a later phase describes
     * the world as it then is rather than adding to the previous one. That is what makes a
     * re-scan phase a genuine re-scan.
     */
    private void applySeed(JsonNode seed) {
        osvRepository.deleteAll();

        for (JsonNode node : seed.path("cves")) {
            String id = node.path("id").asText();
            Vulnerability cve = cveRepository.findById(id).orElseGet(() -> {
                Vulnerability fresh = new Vulnerability();
                fresh.setId(id);
                return fresh;
            });
            cve.setDescription(node.path("description").asText("Golden-set fixture CVE"));
            cve.setBaseSeverity(node.path("baseSeverity").asText(null));
            cve.setCvssScore(node.path("cvssScore").asDouble(0.0d));
            cve.setCveStatus(CveStatus.valueOf(node.path("cveStatus").asText("PUBLISHED")));
            cve.getCpeOperators().clear();
            cveRepository.save(cve);

            if (node.has("epss")) {
                EPSS epss = epssRepository.findById(id).orElseGet(EPSS::new);
                epss.setCve(id);
                epss.setEpss((float) node.path("epss").asDouble());
                epss.setPercentile((float) node.path("epssPercentile").asDouble(0.9d));
                epss.setDate(LocalDateTime.now());
                epssRepository.save(epss);
            }
            if (node.has("kevDueDate")) {
                KEV kev = kevRepository.findById(id).orElseGet(KEV::new);
                kev.setCveId(id);
                kev.setName("Golden-set fixture KEV entry");
                kev.setVendor("fixture");
                kev.setProduct("fixture");
                kev.setAdded(LocalDateTime.now().minusDays(7));
                LocalDate due = LocalDate.parse(node.path("kevDueDate").asText());
                kev.setDueDate(Date.from(due.atStartOfDay(ZoneId.systemDefault()).toInstant()));
                kev.setKnownRansomwareCampaignUse(node.path("knownRansomwareUse").asText("Unknown"));
                kevRepository.save(kev);
            }
        }
        entityManager.flush();

        // CPE rows hang off the CVE through cpe_operator, and cascade from it.
        for (JsonNode node : seed.path("cpe")) {
            Vulnerability cve = cveRepository.findById(node.path("cveId").asText()).orElseThrow();

            CPEOperator operator = new CPEOperator();
            operator.setOperator("OR");
            operator.setNegate(false);
            operator.setCve(cve);

            CPEMatch match = new CPEMatch();
            match.setCriteria(node.path("criteria").asText());
            match.setVulnerable(node.path("vulnerable").asBoolean(true));
            match.setMatchCriteriaId(UUID.randomUUID().toString());
            match.setVersionStartIncluding(text(node, "versionStartIncluding"));
            match.setVersionStartExcluding(text(node, "versionStartExcluding"));
            match.setVersionEndIncluding(text(node, "versionEndIncluding"));
            match.setVersionEndExcluding(text(node, "versionEndExcluding"));
            match.setOperator(operator);

            operator.getCpeMatches().add(match);
            cve.getCpeOperators().add(operator);
            cveRepository.save(cve);
        }

        for (JsonNode node : seed.path("osv")) {
            OsvAdvisory advisory = new OsvAdvisory();
            advisory.setOsvId(node.path("osvId").asText());
            advisory.setEcosystem(node.path("ecosystem").asText());
            advisory.setPackageName(node.path("packageName").asText());
            advisory.setSummary(node.path("summary").asText(null));
            advisory.setModified(LocalDateTime.now());
            advisory.setLastIngestedAt(LocalDateTime.now());
            if (node.has("withdrawn")) {
                advisory.setWithdrawn(LocalDateTime.now());
            }
            for (JsonNode alias : node.path("aliases")) {
                advisory.getAliases().add(alias.asText());
            }
            for (JsonNode version : node.path("versions")) {
                advisory.getVersions().add(version.asText());
            }
            for (JsonNode range : node.path("ranges")) {
                OsvAffectedRange affected = new OsvAffectedRange();
                affected.setAdvisory(advisory);
                affected.setRangeType(range.path("rangeType").asText("ECOSYSTEM"));
                affected.setIntroduced(text(range, "introduced"));
                affected.setFixed(text(range, "fixed"));
                affected.setLastAffected(text(range, "lastAffected"));
                advisory.getRanges().add(affected);
            }
            osvRepository.save(advisory);
        }

        entityManager.flush();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }

}
