package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.OwnershipLinkRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TenantMembershipRepository;
import net.jdesive.secy.persistence.TenantRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.OwnerType;
import net.jdesive.secy.persistence.entity.OwnershipInferenceMethod;
import net.jdesive.secy.persistence.entity.OwnershipLink;
import net.jdesive.secy.persistence.entity.OwnershipSource;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.TenantMembership;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.service.ProductService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code ProductOwnershipController}'s M1b manual ownership API: {@code GET}/{@code POST}
 * {@code /products/{productId}/owners} and {@code DELETE .../{ownerId}}.
 *
 * <p>Most requests here run under {@code @WithMockUser}, whose principal is a plain Spring Security
 * {@code User}, not an {@code AppUserPrincipal} — {@code @AuthenticationPrincipal} resolves it to
 * null (see {@code ActionableTriageControllerTest}'s Javadoc), so the assigning-user tests use a
 * real bearer token instead. A class-level {@code @WithMockUser} shadows a per-request bearer
 * token too — Spring Security Test's MockMvc integration injects the mock context before our
 * {@code JwtAuthenticationFilter} runs, and the filter's "never overwrite an existing authentication"
 * rule then skips the token entirely — so that one test overrides the security context per-request
 * with {@code .with(securityContext(SecurityContextHolder.createEmptyContext()))} to let the real
 * token take effect.
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
class ProductOwnershipControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private OwnershipLinkRepository ownershipLinkRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ProductService productService;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TriageEventRepository triageEventRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    private Product product;
    private User memberUser;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        ownershipLinkRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        triageEventRepository.deleteAll(); // must run before userRepository.deleteAll() -- no cascade on fk_triage_event_changed_by
        userRepository.deleteAll();

        // A distinctive name, not "Acme Web" like several @Transactional test classes use: this class
        // is deliberately NOT @Transactional (mirrors ProductControllerTest), so every write here
        // commits for real. A shared fixture name would risk colliding with a later test class's own
        // deleteAll()-then-insert-in-one-transaction sequence, which Hibernate's flush ordering
        // (entity insertions are flushed before entity deletions, regardless of call order) can lose
        // to a pre-existing row with the same (tenant_id, name).
        Product fresh = new Product();
        fresh.setName("M1b Ownership Test Product");
        product = productService.createProduct(fresh);

        memberUser = saveUser("member@example.com", "Member Person", true);
        addMembership(memberUser);
    }

    /* ------------------------------------------------------------------ */
    /* POST -- USER owner                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    void assigningARegisteredTenantMemberSucceeds() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", memberUser.getId().toString()));

        MvcResult result = mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.productId").value(product.getId().toString()))
                .andExpect(jsonPath("$.ownerType").value("USER"))
                .andExpect(jsonPath("$.userId").value(memberUser.getId().toString()))
                .andExpect(jsonPath("$.userEmail").value("member@example.com"))
                .andExpect(jsonPath("$.userDisplayName").value("Member Person"))
                .andExpect(jsonPath("$.principal").doesNotExist())
                .andExpect(jsonPath("$.source").value("MANUAL"))
                .andExpect(jsonPath("$.inferenceMethod").doesNotExist())
                .andExpect(jsonPath("$.evidence").doesNotExist())
                .andExpect(jsonPath("$.assignedById").doesNotExist())
                .andExpect(jsonPath("$.tenantId").doesNotExist())
                .andReturn();

        JsonNode created = objectMapper.readTree(result.getResponse().getContentAsString());
        UUID linkId = UUID.fromString(created.get("id").asText());

        mockMvc.perform(get("/products/{id}/owners", product.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(linkId.toString()));

        OwnershipLink stored = ownershipLinkRepository.findById(linkId).orElseThrow();
        assertThat(stored.getTenantId()).isEqualTo(Tenant.DEFAULT_TENANT_ID);
    }

    @Test
    void teamOwnerWithPaddedPrincipalIsTrimmedOnStore() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "principal", "  Platform Team  "));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.principal").value("Platform Team"));

        List<OwnershipLink> stored = ownershipLinkRepository.findByProductIdOrderByCreatedAtAsc(product.getId());
        assertThat(stored).hasSize(1);
        assertThat(stored.get(0).getPrincipal()).isEqualTo("Platform Team");
    }

    @Test
    void unknownUserIdIs400AndPersistsNothing() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", UUID.randomUUID().toString()));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void userNotAMemberOfTheTenantIs400() throws Exception {
        User outsider = saveUser("outsider@example.com", "Outsider Person", true);
        // Deliberately no TenantMembership row for outsider.

        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", outsider.getId().toString()));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void disabledUserIs400() throws Exception {
        User disabled = saveUser("disabled@example.com", "Disabled Person", false);
        addMembership(disabled);

        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", disabled.getId().toString()));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void userOwnerCannotAlsoCarryAPrincipalIs400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", memberUser.getId().toString(),
                "principal", "member-github-login"));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    /* ------------------------------------------------------------------ */
    /* POST -- TEAM owner                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    void teamOwnerCannotCarryAUserIdIs400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "userId", memberUser.getId().toString(),
                "principal", "Platform Team"));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void missingOwnerTypeIs400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("userId", memberUser.getId().toString()));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void blankTeamPrincipalIs400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "principal", "   "));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void tooLongTeamPrincipalIs400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "principal", "x".repeat(256)));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    @Test
    void invalidOwnerTypeEnumStringIs400() throws Exception {
        String body = "{\"ownerType\":\"BOGUS\",\"principal\":\"Platform Team\"}";

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    /* ------------------------------------------------------------------ */
    /* Duplicates                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void duplicateManualUserOwnerIs409() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "USER",
                "userId", memberUser.getId().toString()));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());

        assertThat(ownershipLinkRepository.count()).isEqualTo(1);
    }

    @Test
    void duplicateTeamOwnerDifferingOnlyByCaseIs409() throws Exception {
        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerType", "TEAM", "principal", "Platform Team"))))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerType", "TEAM", "principal", "PLATFORM TEAM"))))
                .andExpect(status().isConflict());

        assertThat(ownershipLinkRepository.count()).isEqualTo(1);
    }

    /* ------------------------------------------------------------------ */
    /* Unassigned bucket                                                   */
    /* ------------------------------------------------------------------ */

    @Test
    void assigningAnOwnerToTheUnassignedBucketIs409() throws Exception {
        Product unassigned = productService.getOrCreateUnassigned(Tenant.DEFAULT_TENANT_ID);

        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "principal", "Platform Team"));

        mockMvc.perform(post("/products/{id}/owners", unassigned.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());

        assertThat(ownershipLinkRepository.count()).isZero();
    }

    /* ------------------------------------------------------------------ */
    /* Unknown product                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void unknownProductIdIs404OnGetPostAndDelete() throws Exception {
        UUID unknownId = UUID.randomUUID();

        mockMvc.perform(get("/products/{id}/owners", unknownId))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/products/{id}/owners", unknownId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerType", "TEAM", "principal", "Platform Team"))))
                .andExpect(status().isNotFound());

        mockMvc.perform(delete("/products/{id}/owners/{ownerId}", unknownId, UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* DELETE                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void deletingAManualLinkRemovesIt() throws Exception {
        UUID linkId = assignTeamOwner(product.getId(), "Platform Team");

        mockMvc.perform(delete("/products/{id}/owners/{ownerId}", product.getId(), linkId))
                .andExpect(status().isNoContent());

        assertThat(ownershipLinkRepository.findById(linkId)).isEmpty();
    }

    @Test
    void deletingALinkThroughADifferentProductIs404() throws Exception {
        UUID linkId = assignTeamOwner(product.getId(), "Platform Team");

        Product otherProduct = new Product();
        otherProduct.setName("Other Product");
        otherProduct = productService.createProduct(otherProduct);

        mockMvc.perform(delete("/products/{id}/owners/{ownerId}", otherProduct.getId(), linkId))
                .andExpect(status().isNotFound());

        assertThat(ownershipLinkRepository.findById(linkId)).isPresent();
    }

    @Test
    void deletingAnInferredLinkIs409() throws Exception {
        OwnershipLink inferred = new OwnershipLink();
        inferred.setProduct(product);
        inferred.setOwnerType(OwnerType.TEAM);
        inferred.setPrincipal("@acme/platform");
        inferred.setSource(OwnershipSource.INFERRED);
        inferred.setInferenceMethod(OwnershipInferenceMethod.CODEOWNERS);
        inferred.setEvidence(".github/CODEOWNERS:1");
        inferred.setTenantId(product.getTenantId());
        UUID linkId = ownershipLinkRepository.save(inferred).getId();

        mockMvc.perform(delete("/products/{id}/owners/{ownerId}", product.getId(), linkId))
                .andExpect(status().isConflict());

        assertThat(ownershipLinkRepository.findById(linkId)).isPresent();
    }

    /* ------------------------------------------------------------------ */
    /* Cascades                                                            */
    /* ------------------------------------------------------------------ */

    @Test
    void deletingTheProductCascadesItsOwnershipLinks() {
        UUID linkId = ownershipLinkRepository.save(teamLink(product, "Platform Team")).getId();

        productRepository.deleteById(product.getId());

        assertThat(ownershipLinkRepository.findById(linkId)).isEmpty();
    }

    @Test
    void deletingAUserCascadesOwnedLinksAndNullsAssignedByOnlyLinks() {
        User owner = saveUser("owner-to-delete@example.com", "Owner ToDelete", true);
        addMembership(owner);

        OwnershipLink ownedByDeletedUser = new OwnershipLink();
        ownedByDeletedUser.setProduct(product);
        ownedByDeletedUser.setOwnerType(OwnerType.USER);
        ownedByDeletedUser.setUser(owner);
        ownedByDeletedUser.setSource(OwnershipSource.MANUAL);
        ownedByDeletedUser.setTenantId(product.getTenantId());
        UUID ownedLinkId = ownershipLinkRepository.save(ownedByDeletedUser).getId();

        OwnershipLink assignedByDeletedUserOnly = new OwnershipLink();
        assignedByDeletedUserOnly.setProduct(product);
        assignedByDeletedUserOnly.setOwnerType(OwnerType.TEAM);
        assignedByDeletedUserOnly.setPrincipal("QA Team");
        assignedByDeletedUserOnly.setSource(OwnershipSource.MANUAL);
        assignedByDeletedUserOnly.setAssignedBy(owner);
        assignedByDeletedUserOnly.setTenantId(product.getTenantId());
        UUID assignedByLinkId = ownershipLinkRepository.save(assignedByDeletedUserOnly).getId();

        userRepository.deleteById(owner.getId());

        assertThat(ownershipLinkRepository.findById(ownedLinkId)).isEmpty();
        OwnershipLink survivor = ownershipLinkRepository.findById(assignedByLinkId).orElseThrow();
        assertThat(survivor.getAssignedBy()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* Real bearer token records assignedById                             */
    /* ------------------------------------------------------------------ */

    @Test
    void postWithARealBearerTokenRecordsAssignedById() throws Exception {
        String token = registerAndLogin("ownership-caller@example.com", "correct-horse-battery", "Owner Caller");
        JsonNode me = objectMapper.readTree(
                mockMvc.perform(get("/auth/me")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .with(securityContext(SecurityContextHolder.createEmptyContext())))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
        UUID callerId = UUID.fromString(me.get("id").asText());

        String body = objectMapper.writeValueAsString(Map.of(
                "ownerType", "TEAM",
                "principal", "QA Team"));

        mockMvc.perform(post("/products/{id}/owners", product.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .with(securityContext(SecurityContextHolder.createEmptyContext()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.assignedById").value(callerId.toString()));
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private UUID assignTeamOwner(UUID productId, String principal) throws Exception {
        MvcResult result = mockMvc.perform(post("/products/{id}/owners", productId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ownerType", "TEAM", "principal", principal))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText());
    }

    private static OwnershipLink teamLink(Product product, String principal) {
        OwnershipLink link = new OwnershipLink();
        link.setProduct(product);
        link.setOwnerType(OwnerType.TEAM);
        link.setPrincipal(principal);
        link.setSource(OwnershipSource.MANUAL);
        link.setTenantId(product.getTenantId());
        return link;
    }

    private User saveUser(String email, String displayName, boolean enabled) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash("{noop}unused");
        user.setDisplayName(displayName);
        user.setRole(Role.USER);
        user.setEnabled(enabled);
        return userRepository.save(user);
    }

    private void addMembership(User user) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenantRepository.getReferenceById(Tenant.DEFAULT_TENANT_ID));
        membership.setUser(user);
        tenantMembershipRepository.save(membership);
    }

    private String registerAndLogin(String email, String password, String displayName) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new HashMap<>(Map.of(
                                "email", email, "password", password, "displayName", displayName)))))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("token").asText();
    }
}
