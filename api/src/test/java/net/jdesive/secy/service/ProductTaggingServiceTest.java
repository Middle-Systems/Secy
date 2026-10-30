package net.jdesive.secy.service;

import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.ProductTagConfigRepository;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.ProductTagConfig;
import net.jdesive.secy.persistence.entity.Tenant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link ProductTaggingService}: the tag-key config CRUD, {@link ProductTaggingService#resolveProduct}
 * (M1a's one true resolution seam), and {@link ProductTaggingService#parseTagParams}.
 */
@SpringBootTest
class ProductTaggingServiceTest {

    private static final UUID TENANT = Tenant.DEFAULT_TENANT_ID;

    @Autowired
    private ProductTaggingService productTaggingService;

    @Autowired
    private ProductTagConfigRepository productTagConfigRepository;

    @Autowired
    private ProductRepository productRepository;

    @BeforeEach
    void seed() {
        // Every test class touching ProductTagConfigRepository must clear it, or a custom key set
        // by one test class leaks into the next on the shared H2 database.
        productTagConfigRepository.deleteAll();
        productRepository.deleteAll();
    }

    /* ------------------------------------------------------------------ */
    /* getTagKey / setTagKey                                               */
    /* ------------------------------------------------------------------ */

    @Test
    void getTagKeyDefaultsWhenNoConfigRowExists() {
        assertThat(productTaggingService.getTagKey(TENANT)).isEqualTo(ProductTagConfig.DEFAULT_TAG_KEY);
    }

    @Test
    void setTagKeyPersistsAndUpdatesInPlaceRatherThanDuplicating() {
        productTaggingService.setTagKey(TENANT, "team:owner");
        assertThat(productTaggingService.getTagKey(TENANT)).isEqualTo("team:owner");
        assertThat(productTagConfigRepository.count()).isEqualTo(1);

        productTaggingService.setTagKey(TENANT, "team:owner-v2");
        assertThat(productTaggingService.getTagKey(TENANT)).isEqualTo("team:owner-v2");
        assertThat(productTagConfigRepository.count())
                .as("the same row is updated, not a second one inserted")
                .isEqualTo(1);
    }

    @Test
    void setTagKeyRejectsBlankKeysWithSpacesOrEqualsSigns() {
        assertThatThrownBy(() -> productTaggingService.setTagKey(TENANT, ""))
                .isInstanceOf(InvalidProductTagException.class);
        assertThatThrownBy(() -> productTaggingService.setTagKey(TENANT, "   "))
                .isInstanceOf(InvalidProductTagException.class);
        assertThatThrownBy(() -> productTaggingService.setTagKey(TENANT, "a=b"))
                .isInstanceOf(InvalidProductTagException.class);
        assertThatThrownBy(() -> productTaggingService.setTagKey(TENANT, "has space"))
                .isInstanceOf(InvalidProductTagException.class);
        assertThatThrownBy(() -> productTaggingService.setTagKey(TENANT, "x".repeat(129)))
                .isInstanceOf(InvalidProductTagException.class);
    }

    @Test
    void setTagKeyNeverRetroactivelyChangesAnAlreadyResolvedProduct() {
        Product resolved = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "checkout"));

        productTaggingService.setTagKey(TENANT, "team:owner");

        // Re-resolving the OLD key's value now falls through to the bucket, since the key changed —
        // but the already-created "checkout" product itself is untouched.
        Product reloaded = productRepository.findById(resolved.getId()).orElseThrow();
        assertThat(reloaded.getTagValue()).isEqualTo("checkout");
        assertThat(reloaded.isUnassigned()).isFalse();
    }

    /* ------------------------------------------------------------------ */
    /* resolveProduct                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void noTagsResolveToTheSameBucketProductRepeatedly() {
        Product first = productTaggingService.resolveProduct(TENANT, Map.of());
        Product second = productTaggingService.resolveProduct(TENANT, null);

        assertThat(first.isUnassigned()).isTrue();
        assertThat(second.getId()).isEqualTo(first.getId());
    }

    @Test
    void aBlankTagValueResolvesToTheBucket() {
        Product product = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "   "));
        assertThat(product.isUnassigned()).isTrue();
    }

    @Test
    void theReservedValueUnassignedResolvesToTheBucketCaseInsensitively() {
        Product lower = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "unassigned"));
        Product mixed = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "UnAssigned"));

        assertThat(lower.isUnassigned()).isTrue();
        assertThat(mixed.getId()).isEqualTo(lower.getId());
    }

    @Test
    void aMatchingKeyCaseInsensitivelyCreatesAndReusesAProductByTagValue() {
        Product created = productTaggingService.resolveProduct(TENANT, Map.of("SECY:PRODUCT", "payments"));
        assertThat(created.isUnassigned()).isFalse();
        assertThat(created.getName()).isEqualTo("payments");
        assertThat(created.getTagValue()).isEqualTo("payments");

        Product reused = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "payments"));
        assertThat(reused.getId()).isEqualTo(created.getId());
    }

    @Test
    void adoptsAPreExistingUntaggedManualProductByName() {
        Product manual = new Product();
        manual.setName("legacy-service");
        productRepository.save(manual);

        Product resolved = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "legacy-service"));

        assertThat(resolved.getId()).isEqualTo(manual.getId());
        assertThat(resolved.getTagValue()).isEqualTo("legacy-service");
    }

    @Test
    void aCustomTagKeyRoutesCorrectly() {
        productTaggingService.setTagKey(TENANT, "team:owner");

        Product viaOldKey = productTaggingService.resolveProduct(TENANT, Map.of("secy:product", "ignored"));
        assertThat(viaOldKey.isUnassigned()).as("the old key is no longer consulted").isTrue();

        Product viaNewKey = productTaggingService.resolveProduct(TENANT, Map.of("team:owner", "billing"));
        assertThat(viaNewKey.isUnassigned()).isFalse();
        assertThat(viaNewKey.getTagValue()).isEqualTo("billing");
    }

    /* ------------------------------------------------------------------ */
    /* parseTagParams                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void parseTagParamsHandlesNullAndEmpty() {
        assertThat(ProductTaggingService.parseTagParams(null)).isEmpty();
        assertThat(ProductTaggingService.parseTagParams(List.of())).isEmpty();
    }

    @Test
    void parseTagParamsSplitsOnlyOnTheFirstEquals() {
        Map<String, String> result = ProductTaggingService.parseTagParams(List.of("secy:product=a=b=c"));
        assertThat(result).containsExactly(Map.entry("secy:product", "a=b=c"));
    }

    @Test
    void parseTagParamsTrimsKeysAndValues() {
        Map<String, String> result = ProductTaggingService.parseTagParams(List.of(" secy:product = checkout "));
        assertThat(result).containsExactly(Map.entry("secy:product", "checkout"));
    }

    @Test
    void parseTagParamsRejectsADuplicateKeyCaseInsensitively() {
        assertThatThrownBy(() -> ProductTaggingService.parseTagParams(
                List.of("secy:product=a", "SECY:PRODUCT=b")))
                .isInstanceOf(InvalidProductTagException.class)
                .hasMessageContaining("more than once");
    }

    @Test
    void parseTagParamsRejectsAMalformedEntry() {
        assertThatThrownBy(() -> ProductTaggingService.parseTagParams(List.of("no-equals-sign")))
                .isInstanceOf(InvalidProductTagException.class);
        assertThatThrownBy(() -> ProductTaggingService.parseTagParams(List.of("=blank-key")))
                .isInstanceOf(InvalidProductTagException.class);
    }
}
