package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.ProductTagConfigRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.Tenant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code POST /sbom} (M1a) — the tag-driven upload path that resolves its product from
 * {@code tag=key=value} params rather than a URL path segment. Modeled on
 * {@code SbomUploadFormatTest}, which owns the equivalent synchronous contract for
 * {@code POST /sbom/{productId}/sboms}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
@org.springframework.transaction.annotation.Transactional
class TagDrivenSbomUploadTest {

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
    private ProductRepository productRepository;

    @Autowired
    private ProductTagConfigRepository productTagConfigRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    /**
     * Cleared, not seeded: a leftover asset from another test class in the shared H2 database would
     * otherwise hold a FK on a product this seed deletes.
     */
    @Autowired
    private net.jdesive.secy.persistence.AssetRepository assetRepository;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run. Every test class
        // touching ProductTagConfigRepository must clear it, or a custom key leaks between classes.
        productTagConfigRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
    }

    @Test
    void anUntaggedUploadLandsInTheUnassignedBucketAndStaysActive() throws Exception {
        upload("cyclonedx-mixed.json", null)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("SBOM_UPLOAD"))
                .andExpect(jsonPath("$.status").value("QUEUED"));

        SBOM placeholder = onlySbom();
        Product product = productRepository.findById(placeholder.getProduct().getId()).orElseThrow();
        assertThat(product.isUnassigned()).isTrue();
        assertThat(product.getName()).isEqualTo(Product.UNASSIGNED_NAME);
        assertThat(placeholder.isActive()).isTrue();
    }

    @Test
    void aTaggedUploadWithTheConfiguredKeyLandsOnTheCorrectProduct() throws Exception {
        upload("cyclonedx-mixed.json", "secy:product=checkout-service").andExpect(status().isAccepted());

        SBOM placeholder = onlySbom();
        Product product = productRepository.findById(placeholder.getProduct().getId()).orElseThrow();
        assertThat(product.isUnassigned()).isFalse();
        assertThat(product.getName()).isEqualTo("checkout-service");
        assertThat(product.getTagValue()).isEqualTo("checkout-service");
    }

    @Test
    void twoUntaggedUploadsBothLandInTheBucketActiveWithNoConflict() throws Exception {
        upload("cyclonedx-mixed.json", null).andExpect(status().isAccepted());
        upload("spdx-2.2-minimal.json", null).andExpect(status().isAccepted());

        List<SBOM> all = sbomRepository.findAll();
        assertThat(all).hasSize(2);
        // Both point at the same bucket product, and both are still active — the whole point of
        // skipping deactivateOldSboms for the bucket (see SBOMService#createPlaceholder). If the
        // bucket's product had been treated like a normal product, SBOMRepository
        // .findByProductIdAndActiveTrue would throw IncorrectResultSizeDataAccessException the
        // moment a second row here was queried the normal way.
        assertThat(all).allSatisfy(sbom -> assertThat(sbom.isActive()).isTrue());
        assertThat(all.stream().map(sbom -> sbom.getProduct().getId()).distinct().count()).isEqualTo(1);

        Product bucket = productRepository.findByTenantIdAndUnassignedTrue(Tenant.DEFAULT_TENANT_ID).orElseThrow();
        assertThat(all).allSatisfy(sbom -> assertThat(sbom.getProduct().getId()).isEqualTo(bucket.getId()));
    }

    @Test
    void aMalformedTagParamIs400WithNothingQueued() throws Exception {
        upload("cyclonedx-mixed.json", "not-a-key-value-pair")
                .andExpect(status().isBadRequest());

        assertThat(sbomRepository.findAll()).isEmpty();
        assertThat(productRepository.findAll()).as("no bucket/product created for a rejected request").isEmpty();
    }

    @Test
    void aDuplicateTagKeyIs400WithNothingQueued() throws Exception {
        mockMvc.perform(post("/sbom")
                        .param("tag", "secy:product=a", "secy:product=b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("cyclonedx-mixed.json")))
                .andExpect(status().isBadRequest());

        assertThat(sbomRepository.findAll()).isEmpty();
    }

    @Test
    void anUnparsableDocumentIs400WithNoProductCreated() throws Exception {
        upload("not-an-sbom.json", "secy:product=whatever")
                .andExpect(status().isBadRequest());

        assertThat(sbomRepository.findAll()).isEmpty();
        assertThat(productRepository.findAll())
                .as("the document must fail before the tag is ever resolved to a product")
                .isEmpty();
    }

    private SBOM onlySbom() {
        List<SBOM> all = sbomRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private ResultActions upload(String fixture, String tagParam) throws Exception {
        var request = post("/sbom")
                .param("productVersion", "1.0.0")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture));
        if (tagParam != null) {
            request = request.param("tag", tagParam);
        }
        return mockMvc.perform(request);
    }

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("sbom/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
