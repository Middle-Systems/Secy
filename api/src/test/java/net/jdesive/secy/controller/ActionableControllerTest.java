package net.jdesive.secy.controller;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.persistence.*;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract for {@code GET /actionable} and {@code GET /actionable/{id}}: which rows come back, in
 * what order, and what each filter narrows to.
 *
 * <p>Alerts are seeded with their enrichment already written, the way
 * {@code EnrichmentService} would have left them — this is a test of the query surface, not of the
 * funnel (see {@code EnrichmentServiceTest} for that).
 *
 * <p>{@code @Transactional}: the H2 database is shared across every {@code @SpringBootTest} context
 * in the run, and without per-test rollback this class's fixtures would leak into whatever runs next
 * — the same fix already applied to {@code CompromiseFunnelTest} and {@code AzureSyncServiceTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ActionableControllerTest {

    /**
     * Not used to seed anything — cleared because a {@code compromise_finding} left behind by
     * another test class holds an FK into {@code sbom_component} / {@code asset_component} and
     * would block the deletes below (Phase 6).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private KEVRepository kevRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private ProductRepository productRepository;

    /**
     * Not used to seed anything — cleared so a leftover asset from another test class in the shared
     * H2 database cannot hold a FK on a product this one is about to delete.
     */
    @Autowired
    private AssetRepository assetRepository;

    /** Cleared first: a {@code TriageEvent} holds a FK into both alert tables below (Phase 7). */
    @Autowired
    private TriageEventRepository eventRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private UUID batchProductId;
    private UUID topAlertId;
    private UUID nonActionableAlertId;

    /* ------------------------------------------------------------------ */
    /* Seed                                                               */
    /* ------------------------------------------------------------------ */

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        eventRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        kevRepository.deleteAll();
        epssRepository.deleteAll();

        Product web = product("Acme Web");
        Product batch = product("Acme Batch");
        batchProductId = batch.getId();

        SBOMComponent log4jWeb = component("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        SBOMComponent openssl = component("openssl", "1.1.1", "pkg:generic/openssl@1.1.1");
        SBOMComponent leftpad = component("leftpad", "1.0.0", "pkg:npm/leftpad@1.0.0");
        SBOMComponent guava = component("guava", "30.0", "pkg:maven/com.google.guava/guava@30.0");
        sbom(web, log4jWeb, openssl, leftpad, guava);

        SBOMComponent log4jBatch = component("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        SBOMComponent commons = component("commons-text", "1.9", "pkg:maven/org.apache.commons/commons-text@1.9");
        sbom(batch, log4jBatch, commons);

        // The worst thing in the estate: KEV-listed, near-certain EPSS, overdue, ransomware-linked.
        Vulnerability log4shell = cve("CVE-2099-2001", "CRITICAL", 10.0d);
        kev(log4shell, LocalDate.now().minusDays(30), "Known");
        epss(log4shell, 0.97f, 0.999f);

        Vulnerability epssOnly = cve("CVE-2099-2002", "HIGH", 7.5d);
        epss(epssOnly, 0.55f, 0.98f);

        Vulnerability kevOnly = cve("CVE-2099-2003", "MEDIUM", 5.0d);
        kev(kevOnly, LocalDate.now().plusDays(30), "Unknown");

        Vulnerability quiet = cve("CVE-2099-2004", "CRITICAL", 9.0d);
        epss(quiet, 0.02f, 0.30f);

        Vulnerability pocOnly = cve("CVE-2099-2005", "LOW", 4.0d);
        epss(pocOnly, 0.30f, 0.90f);

        LocalDateTime now = LocalDateTime.now();

        // Same CVE, two products — the "all affected components" block of the detail view.
        topAlertId = alert(log4shell, log4jWeb, now.minusHours(1), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV_AND_EPSS_HIGH);
            a.setEpssScore(0.97d);
            a.setEpssPercentile(0.999d);
            a.setCvssScore(10.0d);
            a.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("2.17.1");
            a.setFixSource(FixSource.SCANNER);
            a.setKevDueDate(LocalDate.now().minusDays(30));
            a.setKnownRansomwareUse("Known");
        });
        alert(log4shell, log4jBatch, now.minusHours(2), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV_AND_EPSS_HIGH);
            a.setEpssScore(0.97d);
            a.setEpssPercentile(0.999d);
            a.setCvssScore(10.0d);
            a.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("2.17.1");
            a.setFixSource(FixSource.SCANNER);
            a.setKevDueDate(LocalDate.now().minusDays(30));
            a.setKnownRansomwareUse("Known");
        });
        alert(epssOnly, openssl, now.minusHours(3), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.55d);
            a.setEpssPercentile(0.98d);
            a.setCvssScore(7.5d);
        });
        // KEV-listed but no EPSS row at all: the null that must sort last, not first.
        alert(kevOnly, leftpad, now.minusHours(4), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV);
            a.setCvssScore(5.0d);
            a.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
            a.setFixState(FixState.NO_FIX);
            a.setKevDueDate(LocalDate.now().plusDays(30));
            a.setKnownRansomwareUse("Unknown");
        });
        alert(pocOnly, commons, now.minusHours(5), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.EPSS_HIGH);
            a.setEpssScore(0.30d);
            a.setEpssPercentile(0.90d);
            a.setCvssScore(4.0d);
            a.setExploitMaturity(ExploitMaturity.POC);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("1.10.0");
            a.setFixSource(FixSource.OSV);
        });
        // High CVSS, but neither KEV nor high EPSS — the whole point is that this never shows up.
        nonActionableAlertId = alert(quiet, guava, now.minusHours(6), a -> {
            a.setCvssScore(9.0d);
            a.setEpssScore(0.02d);
            a.setEpssPercentile(0.30d);
        });

        // Now that the whole class is @Transactional (Phase 7), every request handled below shares
        // this same persistence context with the seeding above. Vulnerability.kev/epss are an
        // unidirectional optional @OneToOne with no mappedBy, which Hibernate cannot truly lazy-load
        // without bytecode enhancement — it resolves them (to null, at the time) the moment each CVE
        // row above was first merged, before its KEV/EPSS rows existed. Left uncleared, the identity
        // map would hand the controller that same stale null back instead of re-querying. flush()
        // first — save() alone only schedules the writes, and clear() without a flush would detach
        // (and so silently drop) every one of them before they ever reached the database.
        entityManager.flush();
        entityManager.clear();
    }

    /* ------------------------------------------------------------------ */
    /* List                                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void theEndpointIsProtected() throws Exception {
        mockMvc.perform(get("/actionable")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/actionable/{id}", topAlertId)).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void onlyActionableRowsAreReturned() throws Exception {
        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.content", hasSize(5)))
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-2004')]", hasSize(0)));
    }

    @Test
    @WithMockUser
    void rowsAreSortedByEpssDescendingWithMissingScoresLast() throws Exception {
        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.content[0].epssScore").value(0.97))
                .andExpect(jsonPath("$.content[1].cveId").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.content[2].cveId").value("CVE-2099-2002"))
                .andExpect(jsonPath("$.content[3].cveId").value("CVE-2099-2005"))
                // No EPSS row — must land at the bottom, not float to the top of a DESC sort.
                .andExpect(jsonPath("$.content[4].cveId").value("CVE-2099-2003"))
                .andExpect(jsonPath("$.content[4].epssScore").doesNotExist());
    }

    @Test
    @WithMockUser
    void theRowCarriesEverythingTheTableRenders() throws Exception {
        mockMvc.perform(get("/actionable").param("size", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(topAlertId.toString()))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.content[0].baseSeverity").value("CRITICAL"))
                .andExpect(jsonPath("$.content[0].cvssScore").value(10.0))
                .andExpect(jsonPath("$.content[0].epssPercentile").value(0.999))
                .andExpect(jsonPath("$.content[0].kev").value(true))
                .andExpect(jsonPath("$.content[0].kevDueDate").isNotEmpty())
                .andExpect(jsonPath("$.content[0].knownRansomwareUse").value("Known"))
                .andExpect(jsonPath("$.content[0].exploitMaturity").value("IN_THE_WILD"))
                .andExpect(jsonPath("$.content[0].fixState").value("FIXED"))
                .andExpect(jsonPath("$.content[0].fixedVersions").value("2.17.1"))
                .andExpect(jsonPath("$.content[0].fixSource").value("SCANNER"))
                .andExpect(jsonPath("$.content[0].actionableReason").value("KEV_AND_EPSS_HIGH"))
                .andExpect(jsonPath("$.content[0].productName").value("Acme Web"))
                .andExpect(jsonPath("$.content[0].componentName").value("log4j-core"))
                .andExpect(jsonPath("$.content[0].componentVersion").value("2.14.1"))
                .andExpect(jsonPath("$.content[0].componentPurl").isNotEmpty())
                .andExpect(jsonPath("$.content[0].createdAt").isNotEmpty());
    }

    @Test
    @WithMockUser
    void resultsArePagedInTheSpringPageShape() throws Exception {
        mockMvc.perform(get("/actionable").param("page", "0").param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.totalPages").value(3))
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2001"));

        mockMvc.perform(get("/actionable").param("page", "2").param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2003"));
    }

    /* ------------------------------------------------------------------ */
    /* Filters                                                            */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void reasonFiltersOnTheExactValue() throws Exception {
        mockMvc.perform(get("/actionable").param("reason", "KEV"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2003"));

        // KEV_AND_EPSS_HIGH is its own value, not a member of KEV.
        mockMvc.perform(get("/actionable").param("reason", "KEV_AND_EPSS_HIGH"))
                .andExpect(jsonPath("$.totalElements").value(2));

        mockMvc.perform(get("/actionable").param("reason", "EPSS_HIGH"))
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    @WithMockUser
    void minCvssExcludesLowerScoresAndNonActionableRowsAlike() throws Exception {
        mockMvc.perform(get("/actionable").param("minCvss", "7.0"))
                .andExpect(status().isOk())
                // The 9.0 CVE is not actionable, so it stays out however high it scores.
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-2004')]", hasSize(0)));
    }

    @Test
    @WithMockUser
    void fixStateFiltersTheFixBadge() throws Exception {
        mockMvc.perform(get("/actionable").param("fixState", "FIXED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3));

        mockMvc.perform(get("/actionable").param("fixState", "NO_FIX"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2003"));

        mockMvc.perform(get("/actionable").param("fixState", "UNKNOWN"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2002"));
    }

    @Test
    @WithMockUser
    void minExploitMaturityIsInclusiveAndOrdered() throws Exception {
        mockMvc.perform(get("/actionable").param("minExploitMaturity", "NONE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(5));

        mockMvc.perform(get("/actionable").param("minExploitMaturity", "POC"))
                .andExpect(jsonPath("$.totalElements").value(4));

        mockMvc.perform(get("/actionable").param("minExploitMaturity", "WEAPONIZED"))
                .andExpect(jsonPath("$.totalElements").value(3));

        mockMvc.perform(get("/actionable").param("minExploitMaturity", "IN_THE_WILD"))
                .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    @WithMockUser
    void productIdScopesToOneProduct() throws Exception {
        mockMvc.perform(get("/actionable").param("productId", batchProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content[0].productName").value("Acme Batch"))
                .andExpect(jsonPath("$.content[1].productName").value("Acme Batch"));
    }

    @Test
    @WithMockUser
    void filtersCombine() throws Exception {
        mockMvc.perform(get("/actionable")
                        .param("productId", batchProductId.toString())
                        .param("minExploitMaturity", "WEAPONIZED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-2001"));
    }

    @Test
    @WithMockUser
    void stateFiltersToTheExactTriageState() throws Exception {
        // Phase 7: every seeded row defaults to OPEN, so an exact-match filter on OPEN returns all
        // five and every other state returns none.
        mockMvc.perform(get("/actionable").param("state", "OPEN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(5));

        mockMvc.perform(get("/actionable").param("state", "RESOLVED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    @WithMockUser
    void defaultListingHidesAResolvedRow() throws Exception {
        VulnerabilityAlert alert = alertRepository.findById(topAlertId).orElseThrow();
        alert.setTriageState(TriageState.RESOLVED);
        alertRepository.save(alert);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(4))
                .andExpect(jsonPath("$.content[?(@.id == '" + topAlertId + "')]", hasSize(0)));
    }

    @Test
    @WithMockUser
    void defaultListingHidesAFalsePositiveRow() throws Exception {
        VulnerabilityAlert alert = alertRepository.findAll().stream()
                .filter(a -> a.getId().equals(topAlertId))
                .findFirst().orElseThrow();
        alert.setTriageState(TriageState.FALSE_POSITIVE);
        alertRepository.save(alert);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(4))
                .andExpect(jsonPath("$.content[?(@.id == '" + topAlertId + "')]", hasSize(0)));
    }

    @Test
    @WithMockUser
    void defaultListingShowsAnAcknowledgedRow() throws Exception {
        VulnerabilityAlert alert = alertRepository.findById(topAlertId).orElseThrow();
        alert.setTriageState(TriageState.ACKNOWLEDGED);
        alertRepository.save(alert);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.content[?(@.id == '" + topAlertId + "')]", hasSize(1)));
    }

    @Test
    @WithMockUser
    void defaultListingHidesAnUnexpiredSnoozeButShowsAnExpiredOne() throws Exception {
        VulnerabilityAlert stillSnoozed = alertRepository.findById(topAlertId).orElseThrow();
        stillSnoozed.setTriageState(TriageState.SNOOZED);
        stillSnoozed.setSnoozedUntil(LocalDateTime.now().plusDays(1));
        alertRepository.save(stillSnoozed);

        VulnerabilityAlert expiredSnooze = alertRepository.findById(nonActionableAlertId).orElseThrow();
        expiredSnooze.setActionable(true);
        expiredSnooze.setActionableReason(ActionableReason.EPSS_HIGH);
        expiredSnooze.setTriageState(TriageState.SNOOZED);
        expiredSnooze.setSnoozedUntil(LocalDateTime.now().minusHours(1));
        alertRepository.save(expiredSnooze);

        mockMvc.perform(get("/actionable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.id == '" + topAlertId + "')]", hasSize(0)))
                .andExpect(jsonPath("$.content[?(@.id == '" + nonActionableAlertId + "')]", hasSize(1)));
    }

    @Test
    @WithMockUser
    void assetIdIsNoLongerANoOp() throws Exception {
        // BREAKING vs Phases 1-2, which documented assetId as accepted-and-ignored because there was
        // no Asset entity to match. There is one now (Phase 4), so an unknown asset id filters to
        // nothing instead of returning the unfiltered list. Every alert in this fixture is
        // SBOM-derived, so any asset id excludes all of them.
        mockMvc.perform(get("/actionable").param("assetId", UUID.randomUUID().toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    @WithMockUser
    void anSbomDerivedRowCarriesNoAsset() throws Exception {
        mockMvc.perform(get("/actionable").param("productId", batchProductId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].assetId").doesNotExist())
                .andExpect(jsonPath("$.content[0].assetName").doesNotExist())
                .andExpect(jsonPath("$.content[0].productName").value("Acme Batch"));
    }

    /* ------------------------------------------------------------------ */
    /* Detail                                                             */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void detailCarriesTheCveEveryAffectedComponentAndTheFeedEvidence() throws Exception {
        mockMvc.perform(get("/actionable/{id}", topAlertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(topAlertId.toString()))
                .andExpect(jsonPath("$.actionable").value(true))
                .andExpect(jsonPath("$.actionableReason").value("KEV_AND_EPSS_HIGH"))
                .andExpect(jsonPath("$.exploitMaturity").value("IN_THE_WILD"))
                .andExpect(jsonPath("$.fixedVersions").value("2.17.1"))
                .andExpect(jsonPath("$.cve.id").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.cve.baseSeverity").value("CRITICAL"))
                .andExpect(jsonPath("$.cve.cvssScore").value(10.0))
                .andExpect(jsonPath("$.cve.description").isNotEmpty())
                // Same CVE, two products.
                .andExpect(jsonPath("$.affectedComponents", hasSize(2)))
                .andExpect(jsonPath("$.affectedComponents[0].name").value("log4j-core"))
                .andExpect(jsonPath("$.affectedComponents[0].productName").isNotEmpty())
                .andExpect(jsonPath("$.kev.cveId").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.kev.knownRansomwareCampaignUse").value("Known"))
                .andExpect(jsonPath("$.kev.dueDate").isNotEmpty())
                .andExpect(jsonPath("$.epss.cve").value("CVE-2099-2001"))
                .andExpect(jsonPath("$.epss.epss").value(0.97))
                .andExpect(jsonPath("$.epss.percentile").value(0.999));
    }

    @Test
    @WithMockUser
    void detailIsReachableForANonActionableAlertToo() throws Exception {
        // The list hides it; a deep link to it must still resolve rather than 404.
        mockMvc.perform(get("/actionable/{id}", nonActionableAlertId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.actionable").value(false))
                .andExpect(jsonPath("$.actionableReason").doesNotExist())
                .andExpect(jsonPath("$.kev").doesNotExist());
    }

    @Test
    @WithMockUser
    void anUnknownAlertIs404() throws Exception {
        mockMvc.perform(get("/actionable/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Seeding helpers                                                    */
    /* ------------------------------------------------------------------ */

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.save(product);
    }

    private SBOMComponent component(String name, String version, String purl) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        return component;
    }

    private void sbom(Product product, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setFormat("CycloneDX");
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        sbomRepository.save(sbom);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded CVE " + id + " for the actionable contract test");
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        cve.setPublished(LocalDateTime.now().minusDays(10));
        cve.setLastModified(LocalDateTime.now().minusDays(1));
        cve.setVulnStatus("Analyzed");
        return cveRepository.save(cve);
    }

    private void kev(Vulnerability cve, LocalDate dueDate, String ransomware) {
        KEV kev = new KEV();
        kev.setCveId(cve.getId());
        kev.setName("Seeded KEV entry for " + cve.getId());
        kev.setVendor("acme");
        kev.setProduct("widget");
        kev.setAdded(LocalDateTime.now().minusDays(5));
        kev.setRequiredActions("Apply updates per vendor instructions.");
        kev.setDueDate(Date.from(dueDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        kev.setKnownRansomwareCampaignUse(ransomware);
        kevRepository.save(kev);
    }

    private void epss(Vulnerability cve, float score, float percentile) {
        EPSS epss = new EPSS();
        epss.setCve(cve.getId());
        epss.setEpss(score);
        epss.setPercentile(percentile);
        epss.setDate(LocalDateTime.now().minusDays(1));
        epssRepository.save(epss);
    }

    private UUID alert(Vulnerability cve,
                       SBOMComponent component,
                       LocalDateTime createdAt,
                       java.util.function.Consumer<VulnerabilityAlert> enrichment) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setCreatedAt(createdAt);
        enrichment.accept(alert);
        return alertRepository.save(alert).getId();
    }

}
