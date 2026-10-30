package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.IdentityConfidence;
import net.jdesive.secy.persistence.entity.IdentityConflictType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentIdentityConflict;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.SecondaryIdentifierType;
import net.jdesive.secy.service.SBOMService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M1c ingest path end to end (ROADMAP.md — "Canonical component identity"): identifiers
 * persisted, Pass A's per-component assessment, Pass B's cross-instance hash-collision sweep, and
 * per-SBOM provenance — all driven through the real {@link SBOMService#ingestDocument}, the same
 * path {@code SBOMController} and {@code GitHubSyncService} both call.
 */
@SpringBootTest
@Transactional
class ComponentIdentityIngestTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /* ------------------------------------------------------------------ */
    /* Pass A, driven off the real fixture used for parsing               */
    /* ------------------------------------------------------------------ */

    @Test
    void theFixtureAssessesExactlyAsExpected() throws IOException {
        Product product = newProduct("identity-fixture");
        UUID sbomId = upload(product, readFixture("cyclonedx-identifiers.json"), "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        assertThat(sbom.getIngestionSource()).isEqualTo(SbomIngestionSource.MANUAL_UPLOAD);
        assertThat(sbom.getLifecycleStage()).isNull();

        SBOMComponent log4j = componentNamed(sbom, "log4j-core");
        assertThat(log4j.getIdentifiers()).hasSize(1);
        assertThat(log4j.getIdentifiers().get(0).getSource()).isEqualTo("cyclonedx:component.cpe");
        assertThat(log4j.getIdentityConfidence()).isEqualTo(IdentityConfidence.CORROBORATED);
        assertThat(log4j.getIdentityConflicts()).isEmpty();

        SBOMComponent lodash = componentNamed(sbom, "lodash");
        assertThat(lodash.getIdentityConfidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(lodash.getIdentityConflicts()).extracting(SBOMComponentIdentityConflict::getConflictType)
                .containsExactlyInAnyOrder(
                        IdentityConflictType.CPE_NAME_MISMATCH, IdentityConflictType.CPE_VERSION_MISMATCH);

        SBOMComponent mux = componentNamed(sbom, "mux");
        assertThat(mux.getIdentityConfidence()).isEqualTo(IdentityConfidence.CORROBORATED);
        assertThat(mux.getIdentityConflicts()).isEmpty();

        SBOMComponent agent = componentNamed(sbom, "acme-agent");
        assertThat(agent.getIdentifiers()).singleElement()
                .satisfies(i -> assertThat(i.getIdentifierType()).isEqualTo(SecondaryIdentifierType.SWID));
        assertThat(agent.getIdentityConfidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(agent.getIdentityConflicts()).extracting(SBOMComponentIdentityConflict::getConflictType)
                .containsExactly(IdentityConflictType.SWID_VERSION_MISMATCH);

        SBOMComponent doubleHash = componentNamed(sbom, "double-hash-comp");
        assertThat(doubleHash.getIdentityConfidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(doubleHash.getIdentityConflicts()).extracting(SBOMComponentIdentityConflict::getConflictType)
                .containsExactly(IdentityConflictType.HASH_ALGORITHM_DISAGREEMENT);

        SBOMComponent noTag = componentNamed(sbom, "no-tagid-comp");
        assertThat(noTag.getIdentifiers()).isEmpty();
        assertThat(noTag.getIdentityConfidence()).isEqualTo(IdentityConfidence.UNCORROBORATED);

        SBOMComponent longCpe = componentNamed(sbom, "long-cpe-comp");
        assertThat(longCpe.getIdentifiers()).isEmpty();
        assertThat(longCpe.getIdentityConfidence()).isEqualTo(IdentityConfidence.UNCORROBORATED);
    }

    /* ------------------------------------------------------------------ */
    /* Pass B — cross-instance hash-identity collisions                   */
    /* ------------------------------------------------------------------ */

    @Test
    void theSameStrongDigestOnTwoDifferentIdentitiesFlagsBothSides() throws IOException {
        String digest = "3".repeat(64);

        Product productA = newProduct("hash-collision-a");
        UUID sbomAId = upload(productA, cycloneDxWithHash("foo", "pkg:npm/foo@1.0.0", digest), "1.0.0");

        Product productB = newProduct("hash-collision-b");
        UUID sbomBId = upload(productB, cycloneDxWithHash("foo-bundle", null, digest), "1.0.0");

        SBOMComponent foo = onlyComponent(sbomAId);
        SBOMComponent fooBundle = onlyComponent(sbomBId);

        assertThat(foo.getIdentityKey()).isEqualTo("npm/foo");
        assertThat(fooBundle.getIdentityKey()).isEqualTo("name/foo-bundle");

        assertThat(fooBundle.getIdentityConfidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(fooBundle.getIdentityConflicts()).hasSize(1);
        SBOMComponentIdentityConflict fromBundle = fooBundle.getIdentityConflicts().get(0);
        assertThat(fromBundle.getConflictType()).isEqualTo(IdentityConflictType.HASH_IDENTITY_COLLISION);
        assertThat(fromBundle.getOtherIdentityKey()).isEqualTo("npm/foo");
        assertThat(fromBundle.getOtherComponentId()).isEqualTo(foo.getId());

        // foo (product A) was persisted and committed-within-transaction before product B's ingest
        // ran, so its side of the collision was written via the bulk-update/mirror-row path rather
        // than through a managed collection — see ComponentIdentityService#flagHashIdentityCollisions.
        assertThat(foo.getIdentityConfidence()).isEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(foo.getIdentityConflicts()).hasSize(1);
        SBOMComponentIdentityConflict fromFoo = foo.getIdentityConflicts().get(0);
        assertThat(fromFoo.getConflictType()).isEqualTo(IdentityConflictType.HASH_IDENTITY_COLLISION);
        assertThat(fromFoo.getOtherIdentityKey()).isEqualTo("name/foo-bundle");
        assertThat(fromFoo.getOtherComponentId()).isEqualTo(fooBundle.getId());
    }

    @Test
    void theSameIdentityWithTheSameDigestIsNotACollision() throws IOException {
        String digest = "4".repeat(64);
        Product product = newProduct("same-key-same-digest");

        upload(product, cycloneDxWithHash("samekey", "pkg:npm/samekey@1.0.0", digest), "1.0.0");
        UUID second = upload(product, cycloneDxWithHash("samekey", "pkg:npm/samekey@1.0.1", digest), "1.0.1");

        SBOMComponent v2 = onlyComponent(second);
        assertThat(v2.getIdentityKey()).isEqualTo("npm/samekey");
        assertThat(v2.getIdentityConfidence()).isNotEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(v2.getIdentityConflicts()).isEmpty();
    }

    @Test
    void theEmptyContentDigestNeverCollidesEvenAcrossDifferentIdentities() throws IOException {
        String emptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        Product productA = newProduct("empty-digest-a");
        UUID sbomAId = upload(productA, cycloneDxWithHash("empty-a", "pkg:npm/empty-a@1.0.0", emptySha256), "1.0.0");
        Product productB = newProduct("empty-digest-b");
        UUID sbomBId = upload(productB, cycloneDxWithHash("empty-b", "pkg:npm/empty-b@1.0.0", emptySha256), "1.0.0");

        assertThat(onlyComponent(sbomAId).getIdentityConflicts()).isEmpty();
        assertThat(onlyComponent(sbomBId).getIdentityConflicts()).isEmpty();
        assertThat(onlyComponent(sbomAId).getIdentityConfidence()).isNotEqualTo(IdentityConfidence.CONFLICTING);
        assertThat(onlyComponent(sbomBId).getIdentityConfidence()).isNotEqualTo(IdentityConfidence.CONFLICTING);
    }

    @Test
    void anMd5MatchAcrossDifferentIdentitiesIsNeverACollision() throws IOException {
        String md5 = "d41d8cd98f00b204e9800998ecf8427e"; // 32 hex chars, a real (empty-string) MD5

        Product productA = newProduct("md5-a");
        UUID sbomAId = upload(productA, cycloneDxWithHash("md5-a-comp", "pkg:npm/md5-a-comp@1.0.0", md5, "MD5"), "1.0.0");
        Product productB = newProduct("md5-b");
        UUID sbomBId = upload(productB, cycloneDxWithHash("md5-b-comp", "pkg:npm/md5-b-comp@1.0.0", md5, "MD5"), "1.0.0");

        assertThat(onlyComponent(sbomAId).getIdentityConflicts()).isEmpty();
        assertThat(onlyComponent(sbomBId).getIdentityConflicts()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private Product newProduct(String name) {
        Product product = new Product();
        product.setName(name + "-" + UUID.randomUUID());
        return productRepository.save(product);
    }

    private UUID upload(Product product, String json, String productVersion) {
        NormalizedSbom document;
        try {
            document = sbomParser.parse(mapper.readTree(json));
        } catch (Exception e) {
            throw new IllegalStateException("fixture is not valid JSON", e);
        }
        SBOM placeholder = sbomService.createPlaceholder(product, document, productVersion, json, null,
                SbomIngestionSource.MANUAL_UPLOAD, null);
        sbomService.ingestDocument(placeholder, document, JobProgress.NOOP);
        entityManager.flush();
        entityManager.clear();
        return placeholder.getId();
    }

    private SBOMComponent componentNamed(SBOM sbom, String name) {
        return sbom.getComponents().stream()
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no component named " + name));
    }

    private SBOMComponent onlyComponent(UUID sbomId) {
        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        assertThat(sbom.getComponents()).hasSize(1);
        return sbom.getComponents().get(0);
    }

    private String readFixture(String name) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("sbom/" + name)) {
            assertThat(in).as("sbom/%s", name).isNotNull();
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static String cycloneDxWithHash(String name, String purl, String sha256Digest) {
        return cycloneDxWithHash(name, purl, sha256Digest, "SHA-256");
    }

    private static String cycloneDxWithHash(String name, String purl, String digest, String algorithm) {
        String purlLine = purl == null ? "" : "\"purl\": \"" + purl + "\",";
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "%s",
                      "version": "1.0.0",
                      %s
                      "hashes": [ { "alg": "%s", "content": "%s" } ]
                    }
                  ]
                }
                """.formatted(name, purlLine, algorithm, digest);
    }

}
