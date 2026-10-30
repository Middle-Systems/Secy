package net.jdesive.secy.service.vex;

import net.jdesive.secy.model.vex.VexStatementRole;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.persistence.entity.VexPrecedencePolicy;
import net.jdesive.secy.persistence.entity.VexStatement;
import net.jdesive.secy.persistence.entity.VexStatus;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Pure unit tests for {@link VexResolver} — no Spring context. */
class VexResolverTest {

    private static final String IDENTITY = "maven/org.apache.logging.log4j:log4j-core";

    private static VexResolver.AlertTarget target() {
        return new VexResolver.AlertTarget("CVE-2099-7001", IDENTITY, "2.14.1", null);
    }

    private static VexStatement statement(VexOrigin origin, String author, VexStatus status, String matchKey,
                                          String matchVersion, LocalDateTime timestamp, int ordinal) {
        VexStatement s = new VexStatement();
        s.setId(UUID.randomUUID());
        s.setOrigin(origin);
        s.setAuthor(author);
        s.setAuthorKey(author == null ? "document:x" : author.toLowerCase());
        s.setStatus(status);
        s.setJustification(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
        s.setMatchKey(matchKey);
        s.setMatchVersion(matchVersion);
        s.setScopeProductId(null);
        s.setStatementTimestamp(timestamp);
        s.setCreatedAt(timestamp);
        s.setOrdinal(ordinal);
        return s;
    }

    @Test
    void noCandidatesResolvesToNone() {
        var resolution = VexResolver.resolve(target(), List.of(), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution).isEqualTo(VexResolver.VexResolution.NONE);
    }

    @Test
    void matchKeyMismatchNeverApplies() {
        VexStatement s = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, "npm/other", null,
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(s), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution).isEqualTo(VexResolver.VexResolution.NONE);
    }

    @Test
    void nullMatchKeyNeverApplies() {
        VexStatement s = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, null, null,
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(s), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution).isEqualTo(VexResolver.VexResolution.NONE);
    }

    @Test
    void versionPinMismatchExcludesTheStatement() {
        VexStatement wrongVersion = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, "9.9.9",
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(wrongVersion), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution).isEqualTo(VexResolver.VexResolution.NONE);
    }

    @Test
    void versionlessStatementAppliesToAnyVersion() {
        VexStatement versionless = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(versionless), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(resolution.winningStatementId()).isEqualTo(versionless.getId());
        assertThat(resolution.roles().get(versionless.getId())).isEqualTo(VexStatementRole.WON);
    }

    @Test
    void vPrefixedVersionMatchesBareVersion() {
        VexStatement s = statement(VexOrigin.TENANT, "acme", VexStatus.FIXED, IDENTITY, "v2.14.1",
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(s), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.FIXED);
    }

    @Test
    void scopeProductMismatchExcludesTheStatement() {
        VexStatement s = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 0);
        s.setScopeProductId(UUID.randomUUID());
        var resolution = VexResolver.resolve(target(), List.of(s), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution).isEqualTo(VexResolver.VexResolution.NONE);
    }

    @Test
    void scopeProductMatchApplies() {
        UUID productId = UUID.randomUUID();
        VexStatement s = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 0);
        s.setScopeProductId(productId);
        var scopedTarget = new VexResolver.AlertTarget("CVE-2099-7001", IDENTITY, "2.14.1", productId);
        var resolution = VexResolver.resolve(scopedTarget, List.of(s), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.NOT_AFFECTED);
    }

    @Test
    void tenantOverVendorPolicyPrefersTenant() {
        VexStatement vendor = statement(VexOrigin.VENDOR, "vendor-co", VexStatus.AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusDays(1), 0);
        VexStatement tenant = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 1);
        var resolution = VexResolver.resolve(target(), List.of(vendor, tenant), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(resolution.winningStatementId()).isEqualTo(tenant.getId());
        assertThat(resolution.roles().get(vendor.getId())).isEqualTo(VexStatementRole.OVERRIDDEN);
        assertThat(resolution.roles().get(tenant.getId())).isEqualTo(VexStatementRole.WON);
    }

    @Test
    void vendorOverTenantPolicyPrefersVendor() {
        VexStatement vendor = statement(VexOrigin.VENDOR, "vendor-co", VexStatus.AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusDays(1), 0);
        VexStatement tenant = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 1);
        var resolution = VexResolver.resolve(target(), List.of(vendor, tenant), VexPrecedencePolicy.VENDOR_OVER_TENANT);
        assertThat(resolution.status()).isEqualTo(VexStatus.AFFECTED);
        assertThat(resolution.winningStatementId()).isEqualTo(vendor.getId());
        assertThat(resolution.roles().get(tenant.getId())).isEqualTo(VexStatementRole.OVERRIDDEN);
    }

    @Test
    void emptyTopTierFallsThroughToTheNextTier() {
        // Only a vendor statement exists; TENANT_OVER_VENDOR has nothing in its top tier, so vendor wins.
        VexStatement vendor = statement(VexOrigin.VENDOR, "vendor-co", VexStatus.FIXED, IDENTITY, null,
                LocalDateTime.now(), 0);
        var resolution = VexResolver.resolve(target(), List.of(vendor), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.FIXED);
        assertThat(resolution.roles().get(vendor.getId())).isEqualTo(VexStatementRole.WON);
    }

    @Test
    void authorSupersessionKeepsOnlyTheNewestPerAuthor() {
        VexStatement older = statement(VexOrigin.TENANT, "acme", VexStatus.UNDER_INVESTIGATION, IDENTITY, null,
                LocalDateTime.now().minusDays(2), 0);
        VexStatement newer = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 1);
        var resolution = VexResolver.resolve(target(), List.of(older, newer), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(resolution.roles().get(older.getId())).isEqualTo(VexStatementRole.SUPERSEDED);
        assertThat(resolution.roles().get(newer.getId())).isEqualTo(VexStatementRole.WON);
    }

    @Test
    void tieBreaksByCreatedAtThenOrdinalThenId() {
        LocalDateTime same = LocalDateTime.now();
        VexStatement first = statement(VexOrigin.TENANT, "acme", VexStatus.AFFECTED, IDENTITY, null, same, 0);
        VexStatement second = statement(VexOrigin.TENANT, "acme", VexStatus.NOT_AFFECTED, IDENTITY, null, same, 1);
        var resolution = VexResolver.resolve(target(), List.of(first, second), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        // Same timestamp: higher ordinal (second) wins the tie-break and supersedes the first.
        assertThat(resolution.roles().get(second.getId())).isEqualTo(VexStatementRole.WON);
        assertThat(resolution.roles().get(first.getId())).isEqualTo(VexStatementRole.SUPERSEDED);
    }

    @Test
    void agreeingSameStatusAuthorsInTheWinningTierAreWonAndAgrees() {
        VexStatement a = statement(VexOrigin.TENANT, "team-a", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusHours(1), 0);
        VexStatement b = statement(VexOrigin.TENANT, "team-b", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 1);
        var resolution = VexResolver.resolve(target(), List.of(a, b), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.conflict()).isFalse();
        assertThat(resolution.status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(resolution.roles().get(b.getId())).isEqualTo(VexStatementRole.WON);
        assertThat(resolution.roles().get(a.getId())).isEqualTo(VexStatementRole.AGREES);
    }

    @Test
    void disagreeingAuthorsInTheWinningTierConflict() {
        VexStatement a = statement(VexOrigin.TENANT, "team-a", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusHours(1), 0);
        VexStatement b = statement(VexOrigin.TENANT, "team-b", VexStatus.AFFECTED, IDENTITY, null,
                LocalDateTime.now(), 1);
        var resolution = VexResolver.resolve(target(), List.of(a, b), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.conflict()).isTrue();
        assertThat(resolution.status()).isNull();
        assertThat(resolution.justification()).isNull();
        assertThat(resolution.winningStatementId()).isNull();
        assertThat(resolution.roles().get(a.getId())).isEqualTo(VexStatementRole.CONFLICTING);
        assertThat(resolution.roles().get(b.getId())).isEqualTo(VexStatementRole.CONFLICTING);
    }

    @Test
    void lowerTierDisagreementIsOverriddenNotConflicting() {
        // Two disagreeing vendor statements, plus a tenant statement — tenant wins outright and the
        // vendor disagreement never surfaces as a conflict, since precedence excludes the whole tier.
        VexStatement vendorA = statement(VexOrigin.VENDOR, "vendor-a", VexStatus.AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusHours(2), 0);
        VexStatement vendorB = statement(VexOrigin.VENDOR, "vendor-b", VexStatus.NOT_AFFECTED, IDENTITY, null,
                LocalDateTime.now().minusHours(1), 1);
        VexStatement tenant = statement(VexOrigin.TENANT, "acme", VexStatus.FIXED, IDENTITY, null,
                LocalDateTime.now(), 2);
        var resolution = VexResolver.resolve(target(), List.of(vendorA, vendorB, tenant), VexPrecedencePolicy.TENANT_OVER_VENDOR);
        assertThat(resolution.conflict()).isFalse();
        assertThat(resolution.status()).isEqualTo(VexStatus.FIXED);
        assertThat(resolution.roles().get(vendorA.getId())).isEqualTo(VexStatementRole.OVERRIDDEN);
        assertThat(resolution.roles().get(vendorB.getId())).isEqualTo(VexStatementRole.OVERRIDDEN);
        assertThat(resolution.roles().get(tenant.getId())).isEqualTo(VexStatementRole.WON);
    }

}
