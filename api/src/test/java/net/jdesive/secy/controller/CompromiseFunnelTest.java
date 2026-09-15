package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.*;
import net.jdesive.secy.persistence.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.function.Consumer;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Phase 6's contract for {@code GET /actionable} as a <b>typed union</b>, and for
 * {@code GET /compromise}.
 *
 * <p>Fixtures are seeded with their enrichment already written, the way {@code EnrichmentService}
 * and {@code CompromiseDetectionService} would have left them — this pins the query surface and the
 * response shape, not the funnel (see {@code EnrichmentServiceTest} and
 * {@code CompromiseDetectionServiceTest} for those).
 *
 * <p>The load-bearing assertion in this class is
 * {@link #aComponentWithOnlyACompromiseFindingIsActionableAndOutranksEveryKevAndEpssRow()}: it is
 * the whole point of the phase, and the one thing a refactor of the two-tier paging could silently
 * break. See {@code PHASE6-CONTRACT.md} §4.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CompromiseFunnelTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

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

    @Autowired
    private AssetRepository assetRepository;

    private UUID productId;
    private UUID otherProductId;
    private UUID assetId;
    private UUID malwareFindingId;
    private UUID maliciousFindingId;
    private UUID investigateFindingId;
    private UUID kevAlertId;

    /* ------------------------------------------------------------------ */
    /* Seed                                                               */
    /* ------------------------------------------------------------------ */

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        cveRepository.deleteAll();
        kevRepository.deleteAll();
        epssRepository.deleteAll();

        Product acme = product("Acme Web");
        Product other = product("Acme Batch");
        productId = acme.getId();
        otherProductId = other.getId();

        SBOMComponent log4j = component("log4j-core", "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        SBOMComponent quietPkg = component("quiet-lib", "1.0.0", "pkg:npm/quiet-lib@1.0.0");
        // The star of the show: a package with NO CVE at all. Nothing in Phases 1-5 could ever have
        // surfaced this, because there is no vulnerability row for it to hang off.
        SBOMComponent maliciousPkg = component("bucket-protocol-sdk-v2", "1.0.26",
                "pkg:npm/bucket-protocol-sdk-v2@1.0.26");
        SBOMComponent malwarePkg = component("innocuous-lib", "1.2.3", "pkg:npm/innocuous-lib@1.2.3");
        sbom(acme, log4j, quietPkg, maliciousPkg, malwarePkg);

        SBOMComponent otherPkg = component("other-bad", "1.0.0", "pkg:npm/other-bad@1.0.0");
        sbom(other, otherPkg);

        Asset image = asset("acme/api:1.4.2");
        assetId = image.getId();
        AssetComponent assetPkg = image.getComponents().get(0);

        // --- vulnerability arm ---
        Vulnerability log4shell = cve("CVE-2099-3001", "CRITICAL", 10.0d);
        kev(log4shell, LocalDate.now().minusDays(30), "Known");
        epss(log4shell, 0.97f, 0.999f);

        LocalDateTime now = LocalDateTime.now();

        // The worst CVE in the estate: KEV-listed, near-certain EPSS. It still sorts BELOW every
        // compromise finding.
        kevAlertId = alert(log4shell, log4j, now.minusHours(1), a -> {
            a.setActionable(true);
            a.setActionableReason(ActionableReason.KEV_AND_EPSS_HIGH);
            a.setEpssScore(0.97d);
            a.setEpssPercentile(0.999d);
            a.setCvssScore(10.0d);
            a.setExploitMaturity(ExploitMaturity.IN_THE_WILD);
            a.setFixState(FixState.FIXED);
            a.setFixedVersions("2.17.1");
            a.setFixSource(FixSource.SCANNER);
            a.setMatchConfidence(MatchConfidence.EXACT);
            a.setKevDueDate(LocalDate.now().minusDays(30));
            a.setKnownRansomwareUse("Known");
        });

        // A non-actionable alert, to prove the funnel still filters the vulnerability arm.
        Vulnerability quiet = cve("CVE-2099-3002", "CRITICAL", 9.0d);
        epss(quiet, 0.02f, 0.30f);
        alert(quiet, quietPkg, now.minusHours(2), a -> {
            a.setActionable(false);
            a.setEpssScore(0.02d);
            a.setCvssScore(9.0d);
        });

        // --- compromise arm ---
        // CONFIRMED malware hash, freshest IOC — the top row of the whole screen.
        malwareFindingId = finding(f -> {
            f.setComponent(malwarePkg);
            f.setType(CompromiseType.MALWARE_HASH);
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setSource("abuse.ch MalwareBazaar");
            f.setIocId("c24ccb6dd7f0b36890b5293f67ffc4756c01925db1532b5aca55fc0a2d0dc963");
            f.setMatchedOn("c24ccb6dd7f0b36890b5293f67ffc4756c01925db1532b5aca55fc0a2d0dc963");
            f.setSummary("Known malware sample: Mirai");
            f.setOrigins("abuse_ch");
            f.setIocFirstSeen(now.minusDays(2));
            f.setIocLastSeen(now.minusHours(1));
            f.setIocConfidence(1.0d);
            f.setCreatedAt(now.minusHours(3));
        });

        // CONFIRMED malicious package, slightly older IOC — second.
        maliciousFindingId = finding(f -> {
            f.setComponent(maliciousPkg);
            f.setType(CompromiseType.MALICIOUS_PACKAGE);
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setSource("OpenSSF Malicious Packages");
            f.setIocId("MAL-2026-4502");
            f.setMatchedOn("pkg:npm/bucket-protocol-sdk-v2@1.0.26");
            f.setSummary("Malicious code in bucket-protocol-sdk-v2 (npm)");
            f.setDetails("postinstall hook fetches and backgrounds an attacker binary.");
            f.setOrigins("amazon-inspector, ghsa-malware");
            f.setReferencesJson("[{\"type\":\"PACKAGE\",\"url\":\"https://www.npmjs.com/package/x\"}]");
            f.setIocFirstSeen(now.minusDays(10));
            f.setIocLastSeen(now.minusDays(2));
            f.setCreatedAt(now.minusHours(4));
        });

        // A decayed one — still shown, still above every CVE, but ranked last within its tier.
        investigateFindingId = finding(f -> {
            f.setAssetComponent(assetPkg);
            f.setType(CompromiseType.MALICIOUS_PACKAGE);
            f.setConfidence(CompromiseConfidence.INVESTIGATE);
            f.setSource("OpenSSF Malicious Packages");
            f.setIocId("MAL-2019-0001");
            f.setMatchedOn("pkg:npm/ancient-pkg@0.0.1");
            f.setSummary("Malicious code in ancient-pkg (npm)");
            f.setIocFirstSeen(now.minusDays(500));
            f.setIocLastSeen(now.minusDays(400));
            f.setAgedAt(now.minusDays(1));
            f.setCreatedAt(now.minusHours(5));
        });

        // An auto-resolved one, in the other product — hidden by default from both endpoints.
        finding(f -> {
            f.setComponent(otherPkg);
            f.setType(CompromiseType.MALICIOUS_PACKAGE);
            f.setConfidence(CompromiseConfidence.CONFIRMED);
            f.setSource("OpenSSF Malicious Packages");
            f.setIocId("MAL-2025-0002");
            f.setMatchedOn("pkg:npm/other-bad@1.0.0");
            f.setSummary("Malicious code in other-bad (npm)");
            f.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            f.setCreatedAt(now.minusHours(6));
        });
    }

    /* ------------------------------------------------------------------ */
    /* The headline: the third promotion path                             */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aComponentWithOnlyACompromiseFindingIsActionableAndOutranksEveryKevAndEpssRow() throws Exception {
        mockMvc.perform(get("/actionable").param("size", "10"))
                .andExpect(status().isOk())
                // 3 active compromise findings + 1 actionable alert. The non-actionable alert and
                // the auto-resolved finding are both excluded.
                .andExpect(jsonPath("$.totalElements").value(4))
                .andExpect(jsonPath("$.content", hasSize(4)))

                // Tier 1, in confidence order, then freshest IOC first.
                .andExpect(jsonPath("$.content[0].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[0].id").value(malwareFindingId.toString()))
                .andExpect(jsonPath("$.content[0].compromiseConfidence").value("CONFIRMED"))
                .andExpect(jsonPath("$.content[1].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[1].id").value(maliciousFindingId.toString()))
                .andExpect(jsonPath("$.content[1].compromiseConfidence").value("CONFIRMED"))
                .andExpect(jsonPath("$.content[2].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[2].id").value(investigateFindingId.toString()))
                .andExpect(jsonPath("$.content[2].compromiseConfidence").value("INVESTIGATE"))

                // Tier 2: even a KEV-listed, 0.97-EPSS, ransomware-linked CVE sits below a decayed
                // compromise finding. A finding says malicious code is ALREADY in the build.
                .andExpect(jsonPath("$.content[3].itemType").value("VULNERABILITY"))
                .andExpect(jsonPath("$.content[3].id").value(kevAlertId.toString()))
                .andExpect(jsonPath("$.content[3].cveId").value("CVE-2099-3001"));
    }

    @Test
    @WithMockUser
    void aCompromiseRowCarriesTheSharedFieldsAndNullsOnlyTheCveShapedOnes() throws Exception {
        mockMvc.perform(get("/actionable").param("size", "10"))
                .andExpect(status().isOk())
                // Shared: description, severity, reason, and the whole component/scope block.
                .andExpect(jsonPath("$.content[1].description")
                        .value("Malicious code in bucket-protocol-sdk-v2 (npm)"))
                .andExpect(jsonPath("$.content[1].baseSeverity").value("CRITICAL"))
                .andExpect(jsonPath("$.content[1].actionableReason").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[1].productId").value(productId.toString()))
                .andExpect(jsonPath("$.content[1].productName").value("Acme Web"))
                .andExpect(jsonPath("$.content[1].assetId").value(nullValue()))
                .andExpect(jsonPath("$.content[1].componentName").value("bucket-protocol-sdk-v2"))
                .andExpect(jsonPath("$.content[1].componentVersion").value("1.0.26"))
                .andExpect(jsonPath("$.content[1].componentPurl")
                        .value("pkg:npm/bucket-protocol-sdk-v2@1.0.26"))

                // The compromise arm.
                .andExpect(jsonPath("$.content[1].compromiseType").value("MALICIOUS_PACKAGE"))
                .andExpect(jsonPath("$.content[1].compromiseSource").value("OpenSSF Malicious Packages"))
                .andExpect(jsonPath("$.content[1].iocId").value("MAL-2026-4502"))
                .andExpect(jsonPath("$.content[1].matchedOn")
                        .value("pkg:npm/bucket-protocol-sdk-v2@1.0.26"))
                .andExpect(jsonPath("$.content[1].iocFirstSeen").exists())
                .andExpect(jsonPath("$.content[1].iocLastSeen").exists())

                // Nulled: everything derived from a CVE that does not exist.
                .andExpect(jsonPath("$.content[1].cveId").value(nullValue()))
                .andExpect(jsonPath("$.content[1].cvssScore").value(nullValue()))
                .andExpect(jsonPath("$.content[1].epssScore").value(nullValue()))
                .andExpect(jsonPath("$.content[1].epssPercentile").value(nullValue()))
                .andExpect(jsonPath("$.content[1].kev").value(false))
                .andExpect(jsonPath("$.content[1].kevDueDate").value(nullValue()))
                .andExpect(jsonPath("$.content[1].exploitMaturity").value(nullValue()))
                .andExpect(jsonPath("$.content[1].fixState").value(nullValue()))
                .andExpect(jsonPath("$.content[1].matchConfidence").value(nullValue()));
    }

    @Test
    @WithMockUser
    void aVulnerabilityRowIsUnchangedFromPhase5ApartFromTheNewDiscriminator() throws Exception {
        // The reason the union is a flat envelope: every Phase 1-5 field keeps its JSON path, so no
        // existing client breaks.
        mockMvc.perform(get("/actionable").param("itemType", "VULNERABILITY"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2099-3001"))
                .andExpect(jsonPath("$.content[0].baseSeverity").value("CRITICAL"))
                .andExpect(jsonPath("$.content[0].cvssScore").value(10.0))
                .andExpect(jsonPath("$.content[0].epssScore").value(0.97))
                .andExpect(jsonPath("$.content[0].kev").value(true))
                .andExpect(jsonPath("$.content[0].knownRansomwareUse").value("Known"))
                .andExpect(jsonPath("$.content[0].exploitMaturity").value("IN_THE_WILD"))
                .andExpect(jsonPath("$.content[0].fixState").value("FIXED"))
                .andExpect(jsonPath("$.content[0].fixedVersions").value("2.17.1"))
                .andExpect(jsonPath("$.content[0].matchConfidence").value("EXACT"))
                .andExpect(jsonPath("$.content[0].actionableReason").value("KEV_AND_EPSS_HIGH"))
                // And the compromise arm is absent.
                .andExpect(jsonPath("$.content[0].compromiseType").value(nullValue()))
                .andExpect(jsonPath("$.content[0].iocId").value(nullValue()));
    }

    /* ------------------------------------------------------------------ */
    /* Paging across the tier boundary                                    */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aPageStraddlingTheTierBoundaryIsServedFromBothQueriesWithNoGapOrDuplicate() throws Exception {
        // size=2 puts the boundary inside page 1: two findings, then one finding + one alert.
        mockMvc.perform(get("/actionable").param("size", "2").param("page", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(4))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.content[0].id").value(malwareFindingId.toString()))
                .andExpect(jsonPath("$.content[1].id").value(maliciousFindingId.toString()));

        mockMvc.perform(get("/actionable").param("size", "2").param("page", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                // The straddle: the last compromise row, then the alert half starting at offset 0.
                .andExpect(jsonPath("$.content[0].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[0].id").value(investigateFindingId.toString()))
                .andExpect(jsonPath("$.content[1].itemType").value("VULNERABILITY"))
                .andExpect(jsonPath("$.content[1].id").value(kevAlertId.toString()));
    }

    @Test
    @WithMockUser
    void aPageEntirelyPastTheCompromiseTierOffsetsIntoTheAlertQuery() throws Exception {
        // size=1, page=3 is one past the three findings — the alert half at offset 0.
        mockMvc.perform(get("/actionable").param("size", "1").param("page", "3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(4))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"))
                .andExpect(jsonPath("$.content[0].id").value(kevAlertId.toString()));

        // And one past the end is empty rather than wrapping.
        mockMvc.perform(get("/actionable").param("size", "1").param("page", "4"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)));
    }

    /* ------------------------------------------------------------------ */
    /* Filtering across the union                                         */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aFilterOnlyOneArmCanSatisfyExcludesTheOtherArmFromTheCountAsWellAsTheContent() throws Exception {
        // minCvss asks about CVSS. A compromise finding has none, so returning it anyway — because
        // "it is critical, surely they want it" — would make the filter a lie. It must not appear in
        // totalElements either, or the page count is wrong for a page that never arrives.
        mockMvc.perform(get("/actionable").param("minCvss", "7.0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"));

        mockMvc.perform(get("/actionable").param("fixState", "FIXED"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"));

        mockMvc.perform(get("/actionable").param("minExploitMaturity", "POC"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"));

        mockMvc.perform(get("/actionable").param("matchConfidence", "EXACT"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"));

        // The mirror image: `confidence` is compromise-only.
        mockMvc.perform(get("/actionable").param("confidence", "CONFIRMED"))
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content[0].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[1].itemType").value("COMPROMISE"));
    }

    @Test
    @WithMockUser
    void reasonCompromiseIsEquivalentToItemTypeCompromise() throws Exception {
        mockMvc.perform(get("/actionable").param("reason", "COMPROMISE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[0].itemType").value("COMPROMISE"));

        mockMvc.perform(get("/actionable").param("itemType", "COMPROMISE"))
                .andExpect(jsonPath("$.totalElements").value(3));

        // And a vulnerability reason still excludes the compromise arm.
        mockMvc.perform(get("/actionable").param("reason", "KEV_AND_EPSS_HIGH"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].itemType").value("VULNERABILITY"));
    }

    @Test
    @WithMockUser
    void scopeFiltersApplyToBothArmsIdentically() throws Exception {
        // productId: two findings and one alert in Acme Web; nothing from the asset or Acme Batch.
        mockMvc.perform(get("/actionable").param("productId", productId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[0].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[1].itemType").value("COMPROMISE"))
                .andExpect(jsonPath("$.content[2].itemType").value("VULNERABILITY"));

        // assetId: only the asset-side finding.
        mockMvc.perform(get("/actionable").param("assetId", assetId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(investigateFindingId.toString()))
                .andExpect(jsonPath("$.content[0].assetId").value(assetId.toString()))
                .andExpect(jsonPath("$.content[0].productId").value(nullValue()));

        // The other product's only finding is auto-resolved, so its page is empty.
        mockMvc.perform(get("/actionable").param("productId", otherProductId.toString()))
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    /* ------------------------------------------------------------------ */
    /* The detail hop                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aCompromiseIdIs404OnActionableDetailAndFoundOnCompromiseDetail() throws Exception {
        // Two arms, two detail endpoints. /actionable/{id} returns the full CVE, every component it
        // affects and the KEV/EPSS evidence — none of which a finding has, so a mostly-null body
        // would be worse than a 404. The row's itemType is what routes the client.
        mockMvc.perform(get("/actionable/" + maliciousFindingId))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/compromise/" + maliciousFindingId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(maliciousFindingId.toString()))
                .andExpect(jsonPath("$.type").value("MALICIOUS_PACKAGE"))
                .andExpect(jsonPath("$.confidence").value("CONFIRMED"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.details")
                        .value("postinstall hook fetches and backgrounds an attacker binary."))
                .andExpect(jsonPath("$.origins").value("amazon-inspector, ghsa-malware"))
                .andExpect(jsonPath("$.referencesJson").exists())
                .andExpect(jsonPath("$.productName").value("Acme Web"));

        // And an alert id is not a compromise finding.
        mockMvc.perform(get("/compromise/" + kevAlertId))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* GET /compromise                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void compromiseListDefaultsToActiveAndSortsByConfidenceThenFreshestIoc() throws Exception {
        mockMvc.perform(get("/compromise"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[0].id").value(malwareFindingId.toString()))
                .andExpect(jsonPath("$.content[1].id").value(maliciousFindingId.toString()))
                .andExpect(jsonPath("$.content[2].id").value(investigateFindingId.toString()))
                // The confidence rank is a CASE expression, not an ORDER BY on the column: the enum
                // is persisted as its name, so alphabetical order would put INVESTIGATE (decayed
                // evidence) above LIKELY (live evidence).
                .andExpect(jsonPath("$.content[0].confidence").value("CONFIRMED"))
                .andExpect(jsonPath("$.content[2].confidence").value("INVESTIGATE"));
    }

    @Test
    @WithMockUser
    void compromiseListFiltersByTypeConfidenceScopeAndComponent() throws Exception {
        mockMvc.perform(get("/compromise").param("type", "MALWARE_HASH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(malwareFindingId.toString()));

        mockMvc.perform(get("/compromise").param("confidence", "INVESTIGATE"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(investigateFindingId.toString()))
                // A non-null agedAt next to INVESTIGATE is how the UI explains the demotion.
                .andExpect(jsonPath("$.content[0].agedAt").exists());

        mockMvc.perform(get("/compromise").param("productId", productId.toString()))
                .andExpect(jsonPath("$.totalElements").value(2));

        mockMvc.perform(get("/compromise").param("assetId", assetId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].assetName").value("acme/api:1.4.2"));

        // componentId matches either kind, so a caller holding an id off an /actionable row does not
        // need to know which table it came from.
        UUID sbomComponentId = findingRepository.findById(maliciousFindingId)
                .orElseThrow().getComponent().getId();
        mockMvc.perform(get("/compromise").param("componentId", sbomComponentId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(maliciousFindingId.toString()));

        UUID assetComponentId = findingRepository.findById(investigateFindingId)
                .orElseThrow().getAssetComponent().getId();
        mockMvc.perform(get("/compromise").param("componentId", assetComponentId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].id").value(investigateFindingId.toString()));
    }

    @Test
    @WithMockUser
    void compromiseListPagesAndCanShowAutoResolvedHistory() throws Exception {
        mockMvc.perform(get("/compromise").param("size", "2").param("page", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.content", hasSize(2)));

        mockMvc.perform(get("/compromise").param("size", "2").param("page", "1"))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].id").value(investigateFindingId.toString()));

        // Auto-resolved rows are hidden by default but never deleted — this is the only way to see
        // what a re-scan stopped reproducing.
        mockMvc.perform(get("/compromise").param("lifecycleState", "AUTO_RESOLVED"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].iocId").value("MAL-2025-0002"))
                .andExpect(jsonPath("$.content[0].lifecycleState").value("AUTO_RESOLVED"));
    }

    /* ------------------------------------------------------------------ */
    /* Dashboard                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void theDashboardGainsACompromiseTileThatDoesNotDisturbTheActionableRollUps() throws Exception {
        mockMvc.perform(get("/stats/dashboard"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.compromiseFindingCount").value(3))
                .andExpect(jsonPath("$.compromiseConfirmedCount").value(2))
                .andExpect(jsonPath("$.compromiseInvestigateCount").value(1))
                .andExpect(jsonPath("$.compromiseCreatedLast7d").value(3))
                // Deliberately NOT folded in: every other actionable number counts vulnerability_alert
                // rows, and the severity/fix/maturity breakdowns below would stop adding up.
                .andExpect(jsonPath("$.openActionableCount").value(1));
    }

    /* ------------------------------------------------------------------ */
    /* Fixtures                                                           */
    /* ------------------------------------------------------------------ */

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.saveAndFlush(product);
    }

    private SBOM sbom(Product product, SBOMComponent... components) {
        SBOM sbom = new SBOM();
        sbom.setProduct(product);
        sbom.setActive(true);
        sbom.setStatus("COMPLETED");
        for (SBOMComponent component : components) {
            component.setSbom(sbom);
            sbom.getComponents().add(component);
        }
        return sbomRepository.saveAndFlush(sbom);
    }

    private static SBOMComponent component(String name, String version, String purl) {
        SBOMComponent component = new SBOMComponent();
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        return component;
    }

    private Asset asset(String name) {
        Asset asset = new Asset();
        asset.setType(AssetType.CONTAINER_IMAGE);
        asset.setName(name);
        AssetComponent component = new AssetComponent();
        component.setAsset(asset);
        component.setName("ancient-pkg");
        component.setVersion("0.0.1");
        component.setPurl("pkg:npm/ancient-pkg@0.0.1");
        component.setSource(AssetComponentSource.TRIVY);
        component.setPresentInLastScan(true);
        asset.getComponents().add(component);
        return assetRepository.saveAndFlush(asset);
    }

    private Vulnerability cve(String id, String severity, double cvss) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setBaseSeverity(severity);
        cve.setCvssScore(cvss);
        cve.setDescription("Seeded by CompromiseFunnelTest: " + id);
        cve.setLastModified(LocalDateTime.now());
        return cveRepository.save(cve);
    }

    private void kev(Vulnerability cve, LocalDate dueDate, String ransomware) {
        KEV kev = new KEV();
        kev.setCveId(cve.getId());
        kev.setVendor("Apache");
        kev.setProduct("Log4j");
        kev.setName(cve.getId());
        kev.setDueDate(java.sql.Date.valueOf(dueDate));
        kev.setKnownRansomwareCampaignUse(ransomware);
        kevRepository.saveAndFlush(kev);
    }

    private void epss(Vulnerability cve, float score, float percentile) {
        EPSS epss = new EPSS();
        epss.setCve(cve.getId());
        epss.setEpss(score);
        epss.setPercentile(percentile);
        epss.setDate(LocalDateTime.now());
        epssRepository.saveAndFlush(epss);
    }

    private UUID alert(Vulnerability cve, SBOMComponent component, LocalDateTime createdAt,
                       Consumer<VulnerabilityAlert> customise) {
        VulnerabilityAlert alert = new VulnerabilityAlert();
        alert.setVulnerability(cve);
        alert.setComponent(component);
        alert.setCreatedAt(createdAt);
        alert.setLifecycleState(AlertLifecycleState.ACTIVE);
        customise.accept(alert);
        return alertRepository.saveAndFlush(alert).getId();
    }

    private UUID finding(Consumer<CompromiseFinding> customise) {
        CompromiseFinding finding = new CompromiseFinding();
        finding.setLifecycleState(AlertLifecycleState.ACTIVE);
        finding.setLastSeenAt(LocalDateTime.now());
        customise.accept(finding);
        return findingRepository.saveAndFlush(finding).getId();
    }

}
