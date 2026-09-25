package net.jdesive.secy.service.vex;

import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.model.vex.ParsedVexStatement;
import net.jdesive.secy.persistence.entity.VexDocumentFormat;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Pure unit tests for the CSAF 2.0 subset, via {@link VexDocumentParser}. */
class CsafVexParserTest {

    private final VexDocumentParser parser = new VexDocumentParser(new VexProperties());

    private ParsedVexDocument parse(String json) {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void knownNotAffectedWithFlagJustificationAndImpactThreat() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme Security", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-001", "version": "1", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {
                        "category": "product_name",
                        "product": {
                          "product_id": "CSAFPID-1",
                          "name": "widget 1.0",
                          "product_identification_helper": {"purl": "pkg:maven/acme/widget@1.0.0"}
                        }
                      }
                    ]
                  },
                  "vulnerabilities": [
                    {
                      "cve": "CVE-2099-7201",
                      "product_status": {"known_not_affected": ["CSAFPID-1"]},
                      "flags": [{"label": "component_not_present", "product_ids": ["CSAFPID-1"]}],
                      "threats": [{"category": "impact", "details": "Not compiled in.", "product_ids": ["CSAFPID-1"]}]
                    }
                  ]
                }
                """);

        assertThat(doc.format()).isEqualTo(VexDocumentFormat.CSAF);
        assertThat(doc.documentKey()).isEqualTo("https://acme.example#ACME-VEX-2026-001");
        assertThat(doc.author()).isEqualTo("Acme Security");
        assertThat(doc.statements()).hasSize(1);

        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.cveId()).isEqualTo("CVE-2099-7201");
        assertThat(s.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(s.justification()).isEqualTo(VexJustification.COMPONENT_NOT_PRESENT);
        assertThat(s.impactStatement()).isEqualTo("Not compiled in.");
        assertThat(s.targetPurl()).isEqualTo("pkg:maven/acme/widget@1.0.0");
    }

    @Test
    void productGroupExpandsFlagToEveryMember() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-002", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {"category": "product_name", "product": {"product_id": "P1", "product_identification_helper": {"purl": "pkg:npm/a@1.0.0"}}},
                      {"category": "product_name", "product": {"product_id": "P2", "product_identification_helper": {"purl": "pkg:npm/b@1.0.0"}}}
                    ],
                    "product_groups": [{"group_id": "G1", "product_ids": ["P1", "P2"]}]
                  },
                  "vulnerabilities": [
                    {
                      "cve": "CVE-2099-7202",
                      "product_status": {"known_not_affected": ["P1", "P2"]},
                      "flags": [{"label": "vulnerable_code_not_present", "group_ids": ["G1"]}]
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(2);
        assertThat(doc.statements()).allSatisfy(s ->
                assertThat(s.justification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_PRESENT));
    }

    @Test
    void oneHopRelationshipResolvesTheMergedProduct() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_security_advisory",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-003", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {"category": "product_name", "product": {"product_id": "COMPONENT-1", "product_identification_helper": {"purl": "pkg:npm/comp@1.0.0"}}},
                      {"category": "product_name", "product": {"product_id": "PLATFORM-1", "name": "Platform 1"}}
                    ],
                    "relationships": [
                      {
                        "category": "default_component_of",
                        "product_reference": "COMPONENT-1",
                        "relates_to_product_reference": "PLATFORM-1",
                        "full_product_name": {"product_id": "MERGED-1", "name": "comp on platform"}
                      }
                    ]
                  },
                  "vulnerabilities": [
                    {
                      "cve": "CVE-2099-7203",
                      "product_status": {"known_affected": ["MERGED-1"]}
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.targetPurl()).isEqualTo("pkg:npm/comp@1.0.0");
        assertThat(s.productRef()).contains("MERGED-1").contains("PLATFORM-1");
    }

    @Test
    void relationshipOfARelationshipIsLeftUnresolved() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-004", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "relationships": [
                      {
                        "category": "default_component_of",
                        "product_reference": "NEVER-REGISTERED",
                        "full_product_name": {"product_id": "MERGED-2", "name": "orphan"}
                      }
                    ]
                  },
                  "vulnerabilities": [
                    {
                      "cve": "CVE-2099-7204",
                      "product_status": {"known_affected": ["MERGED-2"]}
                    }
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isNull();
        assertThat(doc.warnings()).anyMatch(w -> w.contains("Unresolvable"));
    }

    @Test
    void contradictoryProductStatusSkipsTheProduct() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-005", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {"category": "product_name", "product": {"product_id": "P1", "product_identification_helper": {"purl": "pkg:npm/x@1.0.0"}}}
                    ]
                  },
                  "vulnerabilities": [
                    {
                      "cve": "CVE-2099-7205",
                      "product_status": {"known_affected": ["P1"], "known_not_affected": ["P1"]}
                    }
                  ]
                }
                """));
    }

    @Test
    void versionRangeProductIsStoredUnmatchable() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-006", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {
                        "category": "product_version_range",
                        "product": {"product_id": "RANGE-1", "name": "1.x", "product_identification_helper": {"purl": "pkg:npm/x@1.x"}}
                      }
                    ]
                  },
                  "vulnerabilities": [
                    {"cve": "CVE-2099-7206", "product_status": {"known_affected": ["RANGE-1"]}}
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        assertThat(doc.statements().get(0).targetPurl()).isNull();
        assertThat(doc.warnings()).anyMatch(w -> w.contains("product_version_range"));
    }

    @Test
    void cpeOnlyProductIsStoredUnmatchableButCpeIsRecorded() {
        ParsedVexDocument doc = parse("""
                {
                  "document": {
                    "csaf_version": "2.0",
                    "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-007", "current_release_date": "2026-01-01T00:00:00Z"}
                  },
                  "product_tree": {
                    "branches": [
                      {"category": "product_name", "product": {"product_id": "CPE-1", "product_identification_helper": {"cpe": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}}}
                    ]
                  },
                  "vulnerabilities": [
                    {"cve": "CVE-2099-7207", "product_status": {"known_affected": ["CPE-1"]}}
                  ]
                }
                """);
        assertThat(doc.statements()).hasSize(1);
        ParsedVexStatement s = doc.statements().get(0);
        assertThat(s.targetPurl()).isNull();
        assertThat(s.targetCpe()).isEqualTo("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*");
    }

    @Test
    void unknownCsafVersionIsRejected() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {"document": {"csaf_version": "2.1", "category": "csaf_vex",
                  "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                  "tracking": {"id": "X", "current_release_date": "2026-01-01T00:00:00Z"}},
                 "vulnerabilities": [{"cve": "CVE-2099-7208", "product_status": {"known_affected": ["P1"]}}]}
                """));
    }

    @Test
    void csafBaseCategoryIsRejected() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {"document": {"csaf_version": "2.0", "category": "csaf_base",
                  "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                  "tracking": {"id": "X", "current_release_date": "2026-01-01T00:00:00Z"}},
                 "vulnerabilities": [{"cve": "CVE-2099-7209", "product_status": {"known_affected": ["P1"]}}]}
                """));
    }

    @Test
    void vulnerabilityWithNoCveFieldIsSkippedEvenWithIdsPresent() {
        assertThrows(VexDocumentRejectedException.class, () -> parse("""
                {
                  "document": {"csaf_version": "2.0", "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-008", "current_release_date": "2026-01-01T00:00:00Z"}},
                  "product_tree": {"branches": [{"category": "product_name", "product": {"product_id": "P1", "product_identification_helper": {"purl": "pkg:npm/x@1.0.0"}}}]},
                  "vulnerabilities": [{"ids": [{"system_name": "GH", "text": "GHSA-xxxx"}], "product_status": {"known_affected": ["P1"]}}]
                }
                """));
    }

    @Test
    void branchDepthOverLimitIsRejected() {
        VexProperties props = new VexProperties();
        props.setMaxBranchDepth(2);
        VexDocumentParser shallow = new VexDocumentParser(props);
        String deepBranches = """
                {"category": "vendor", "product": null, "branches":
                  [{"category": "product_family", "branches":
                    [{"category": "product_name", "product": {"product_id": "TOO-DEEP", "product_identification_helper": {"purl": "pkg:npm/x@1.0.0"}}}]
                  }]
                }
                """;
        String json = """
                {
                  "document": {"csaf_version": "2.0", "category": "csaf_vex",
                    "publisher": {"name": "Acme", "namespace": "https://acme.example"},
                    "tracking": {"id": "ACME-VEX-2026-009", "current_release_date": "2026-01-01T00:00:00Z"}},
                  "product_tree": {"branches": [%s]},
                  "vulnerabilities": [{"cve": "CVE-2099-7210", "product_status": {"known_affected": ["TOO-DEEP"]}}]
                }
                """.formatted(deepBranches);
        assertThrows(VexDocumentRejectedException.class, () -> shallow.parse(json.getBytes(StandardCharsets.UTF_8)));
    }

}
