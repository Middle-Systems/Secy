package net.jdesive.secy.service;

import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.OwnershipLinkRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.OwnerType;
import net.jdesive.secy.persistence.entity.OwnershipLink;
import net.jdesive.secy.persistence.entity.OwnershipSource;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link OwnershipService#productIdsOwnedBy}: the schema-level proof behind M1k's "software
 * engineer sees only their products" acceptance criterion — no caller exists for this seam yet.
 */
@SpringBootTest
class OwnershipServiceTest {

    @Autowired
    private OwnershipService ownershipService;

    @Autowired
    private OwnershipLinkRepository ownershipLinkRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private AppUserRepository userRepository;

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

    @BeforeEach
    void seed() {
        ownershipLinkRepository.deleteAll();
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        sbomRepository.deleteAll();
        productRepository.deleteAll();
        triageEventRepository.deleteAll(); // before userRepository.deleteAll() -- no cascade on fk_triage_event_changed_by
        userRepository.deleteAll();
    }

    @Test
    void productIdsOwnedByReturnsExactlyTheProductsAUserManuallyOwns() {
        User userA = user("a@example.com");
        User userB = user("b@example.com");

        Product p1 = product("P1");
        Product p2 = product("P2");
        Product p3 = product("P3");

        save(userLink(p1, userA));
        save(userLink(p2, userA));
        save(userLink(p2, userB));
        save(teamLink(p3, "Platform Team"));

        List<UUID> ownedByA = ownershipService.productIdsOwnedBy(Tenant.DEFAULT_TENANT_ID, userA.getId());
        List<UUID> ownedByB = ownershipService.productIdsOwnedBy(Tenant.DEFAULT_TENANT_ID, userB.getId());

        assertThat(ownedByA).containsExactlyInAnyOrder(p1.getId(), p2.getId());
        assertThat(ownedByB).containsExactly(p2.getId());
    }

    @Test
    void aPrincipalOnlyInferredUserRowSavesButIsExcludedFromProductIdsOwnedBy() {
        User userA = user("a@example.com");
        Product p1 = product("P1");
        save(userLink(p1, userA));

        Product p2 = product("P2");
        OwnershipLink principalOnly = new OwnershipLink();
        principalOnly.setProduct(p2);
        principalOnly.setOwnerType(OwnerType.USER);
        principalOnly.setPrincipal("alice");
        principalOnly.setSource(OwnershipSource.INFERRED);
        principalOnly.setInferenceMethod(net.jdesive.secy.persistence.entity.OwnershipInferenceMethod.CODEOWNERS);
        principalOnly.setTenantId(p2.getTenantId());
        OwnershipLink saved = ownershipLinkRepository.save(principalOnly);
        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getUser()).isNull();

        List<UUID> ownedByA = ownershipService.productIdsOwnedBy(Tenant.DEFAULT_TENANT_ID, userA.getId());

        assertThat(ownedByA).containsExactly(p1.getId());
    }

    private User user(String email) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash("{noop}unused");
        user.setDisplayName(email);
        user.setRole(Role.USER);
        user.setEnabled(true);
        return userRepository.save(user);
    }

    private Product product(String name) {
        Product product = new Product();
        product.setName(name);
        return productRepository.save(product);
    }

    private static OwnershipLink userLink(Product product, User user) {
        OwnershipLink link = new OwnershipLink();
        link.setProduct(product);
        link.setOwnerType(OwnerType.USER);
        link.setUser(user);
        link.setSource(OwnershipSource.MANUAL);
        link.setTenantId(product.getTenantId());
        return link;
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

    private OwnershipLink save(OwnershipLink link) {
        return ownershipLinkRepository.save(link);
    }
}
