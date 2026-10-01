package net.jdesive.secy.service.sbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMComponentDependencyRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentDependency;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.service.SBOMService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1l (ROADMAP.md — "Dependency graph preserved"): the ingest-time classification and edge
 * persistence, driven through the real {@link SBOMService#ingestDocument} — same "real ingest
 * path" pattern as {@code ComponentIdentityIngestTest}.
 */
@SpringBootTest
@Transactional
class DependencyGraphIngestTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SbomParser sbomParser;

    @Autowired
    private SBOMService sbomService;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private SBOMComponentDependencyRepository dependencyRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void rootToAToBClassifiesCorrectlyAndPersistsExactlyTheEdges() throws IOException {
        Product product = newProduct("dep-graph-chain");
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a", "version": "1.0" },
                    { "type": "library", "bom-ref": "b", "name": "b", "version": "1.0" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "a" ] },
                    { "ref": "a", "dependsOn": [ "b" ] }
                  ] }
                """;
        UUID sbomId = upload(product, json, "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        SBOMComponent a = componentNamed(sbom, "a");
        SBOMComponent b = componentNamed(sbom, "b");

        assertThat(a.getDependencyDepth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(a.getDependencyDistance()).isEqualTo(1);
        assertThat(a.getDependencyPath()).isEqualTo("[\"root\",\"a\"]");

        assertThat(b.getDependencyDepth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(b.getDependencyDistance()).isEqualTo(2);
        assertThat(b.getDependencyPath()).isEqualTo("[\"root\",\"a\",\"b\"]");

        List<SBOMComponentDependency> edges = dependencyRepository.findBySbomId(sbomId);
        assertThat(edges).hasSize(2);
        assertThat(edges).anySatisfy(e -> {
            assertThat(e.getComponentId()).isEqualTo(sbom.getComponent().getId());
            assertThat(e.getDependsOnComponentId()).isEqualTo(a.getId());
        });
        assertThat(edges).anySatisfy(e -> {
            assertThat(e.getComponentId()).isEqualTo(a.getId());
            assertThat(e.getDependsOnComponentId()).isEqualTo(b.getId());
        });
    }

    @Test
    void noDependenciesDocumentClassifiesEveryComponentUnknownWithNoEdgeRows() throws IOException {
        Product product = newProduct("dep-graph-no-deps");
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "components": [
                    { "type": "library", "bom-ref": "a", "name": "a" },
                    { "type": "library", "bom-ref": "b", "name": "b" }
                  ] }
                """;
        UUID sbomId = upload(product, json, "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        for (SBOMComponent c : sbom.getComponents()) {
            assertThat(c.getDependencyDepth()).isEqualTo(DependencyDepth.UNKNOWN);
            assertThat(c.getDependencyDistance()).isNull();
            assertThat(c.getDependencyPath()).isNull();
        }
        assertThat(dependencyRepository.findBySbomId(sbomId)).isEmpty();
    }

    @Test
    void duplicateBomRefsClassifyUnknownAndContributeNoEdges() throws IOException {
        Product product = newProduct("dep-graph-dup-ref");
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "library", "bom-ref": "dup", "name": "dup-one", "version": "1.0" },
                    { "type": "library", "bom-ref": "dup", "name": "dup-two", "version": "2.0" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "dup" ] }
                  ] }
                """;
        UUID sbomId = upload(product, json, "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        // sbom.getComponents() is a plain mappedBy="sbom" query, so it includes the root row too
        // (same reason LineageSourceReader has to filter it out explicitly) -- the root's dependency
        // fields are deliberately left null (never correlated), so only the two "dup" rows assert.
        UUID rootId = sbom.getComponent().getId();
        List<SBOMComponent> dups = sbom.getComponents().stream().filter(c -> !c.getId().equals(rootId)).toList();
        assertThat(dups).hasSize(2);
        for (SBOMComponent c : dups) {
            assertThat(c.getDependencyDepth()).as("component id=%s name=%s bomRef=%s", c.getId(), c.getName(), c.getBomRef())
                    .isEqualTo(DependencyDepth.UNKNOWN);
        }
        assertThat(dependencyRepository.findBySbomId(sbomId)).isEmpty();
    }

    @Test
    void rootRepeatedInComponentsKeepsItsOutgoingEdges() throws IOException {
        Product product = newProduct("dep-graph-root-repeated");
        String json = """
                { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "root" } },
                  "components": [
                    { "type": "application", "bom-ref": "root", "name": "root-dup" },
                    { "type": "library", "bom-ref": "a", "name": "a" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": [ "a" ] }
                  ] }
                """;
        UUID sbomId = upload(product, json, "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        SBOMComponent a = componentNamed(sbom, "a");
        assertThat(a.getDependencyDepth()).isEqualTo(DependencyDepth.DIRECT);

        List<SBOMComponentDependency> edges = dependencyRepository.findBySbomId(sbomId);
        assertThat(edges).hasSize(1);
        assertThat(edges.get(0).getComponentId()).isEqualTo(sbom.getComponent().getId());
        assertThat(edges.get(0).getDependsOnComponentId()).isEqualTo(a.getId());
    }

    @Test
    void syftStyleSpdxClassificationFollowsDependencyOfOnly() throws IOException {
        Product product = newProduct("dep-graph-spdx-syft");
        String json = """
                { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
                  "creationInfo": { "creators": [ "Tool: syft" ] },
                  "documentDescribes": [ "SPDXRef-Package-root" ],
                  "packages": [
                    { "SPDXID": "SPDXRef-Package-root", "name": "root", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1.0" },
                    { "SPDXID": "SPDXRef-Package-b", "name": "b", "versionInfo": "1.0" }
                  ],
                  "relationships": [
                    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" },
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-a" },
                    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-b" },
                    { "spdxElementId": "SPDXRef-Package-a", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Package-root" }
                  ] }
                """;
        UUID sbomId = upload(product, json, "1.0.0");

        SBOM sbom = sbomRepository.findByIdWithComponents(sbomId).orElseThrow();
        SBOMComponent a = componentNamed(sbom, "a");
        SBOMComponent b = componentNamed(sbom, "b");
        assertThat(a.getDependencyDepth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(b.getDependencyDepth()).isEqualTo(DependencyDepth.UNKNOWN);

        List<SBOMComponentDependency> edges = dependencyRepository.findBySbomId(sbomId);
        assertThat(edges).hasSize(1);
        assertThat(edges.get(0).getDependsOnComponentId()).isEqualTo(a.getId());
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

}
