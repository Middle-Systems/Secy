package net.jdesive.secy.persistence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.persistence.entity.SourceConnectorType;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TenantMembership;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M0 — Tenancy foundation (schema only): the default tenant exists and is seeded correctly, new
 * {@link net.jdesive.secy.persistence.entity.TenantOwnedEntity} rows default onto it via
 * {@code @PrePersist} with no request-scoped tenant context needed, per-tenant uniqueness still
 * holds where the old global constraints used to, registration wires up exactly one
 * {@link TenantMembership}, and the tenant columns never leak into a response body. See
 * ROADMAP.md's "M0 — Tenancy foundation (schema only)".
 */
@SpringBootTest
@AutoConfigureMockMvc
class TenancyFoundationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SourceConnectorRepository sourceConnectorRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private AppUserRepository userRepository;

    @BeforeEach
    void cleanUp() {
        // The H2 database is shared by every @SpringBootTest context in the run — start from a
        // known state. Deleting users cascades their tenant_membership rows at the DB level (see
        // TenantMembership.user's @OnDelete), so no explicit membership cleanup is needed.
        productRepository.deleteAll();
        sourceConnectorRepository.deleteAll();
        assetRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void defaultTenantIsSeeded() {
        Tenant tenant = tenantRepository.findById(Tenant.DEFAULT_TENANT_ID).orElseThrow();
        assertThat(tenant.getSlug()).isEqualTo(Tenant.DEFAULT_TENANT_SLUG);
    }

    @Test
    void newProductDefaultsToTheDefaultTenant() {
        Product product = new Product();
        product.setName("acme-widgets");
        Product saved = productRepository.save(product);

        assertThat(saved.getTenantId()).isEqualTo(Tenant.DEFAULT_TENANT_ID);
    }

    @Test
    void newSourceConnectorDefaultsToTheDefaultTenant() {
        SourceConnector connector = new SourceConnector();
        connector.setType(SourceConnectorType.GITHUB);
        connector.setName("Acme org");
        connector.setScope("acme");
        SourceConnector saved = sourceConnectorRepository.save(connector);

        assertThat(saved.getTenantId()).isEqualTo(Tenant.DEFAULT_TENANT_ID);
    }

    @Test
    void newAssetDefaultsToTheDefaultTenant() {
        Asset asset = new Asset();
        asset.setType(AssetType.HOST);
        asset.setName("db-01");
        Asset saved = assetRepository.save(asset);

        assertThat(saved.getTenantId()).isEqualTo(Tenant.DEFAULT_TENANT_ID);
    }

    @Test
    void productNameUniquenessIsStillEnforcedWithinATenant() {
        Product first = new Product();
        first.setName("duplicate-name");
        productRepository.saveAndFlush(first);

        Product second = new Product();
        second.setName("duplicate-name");

        assertThatThrownBy(() -> productRepository.saveAndFlush(second))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void registrationCreatesExactlyOneDefaultTenantMembership() throws Exception {
        JsonNode body = register("tenancy-membership-test@example.com");
        UUID userId = UUID.fromString(body.get("user").get("id").asText());

        List<TenantMembership> memberships = tenantMembershipRepository.findByUserId(userId);

        assertThat(memberships).hasSize(1);
        assertThat(memberships.get(0).getTenant().getId()).isEqualTo(Tenant.DEFAULT_TENANT_ID);
    }

    @Test
    void productListingNeverSerializesTenantFields() throws Exception {
        Product product = new Product();
        product.setName("visible-product");
        productRepository.save(product);

        JsonNode body = register("tenancy-json-test@example.com");
        String token = body.get("token").asText();

        mockMvc.perform(get("/products").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].tenantId").doesNotExist())
                .andExpect(jsonPath("$[0].tenant").doesNotExist());
    }

    private JsonNode register(String email) throws Exception {
        Map<String, Object> payload = Map.of("email", email, "password", "correct-horse-battery");
        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }
}
