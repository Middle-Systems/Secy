package net.jdesive.secy.service.finding;

import net.jdesive.secy.model.finding.FindingFix;
import net.jdesive.secy.model.finding.FixKind;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** M1k's T8 — pure. Every {@link FixKind} branch, including a null {@code fixedVersions}. */
class FindingFixAdvisorTest {

    @Test
    void fixedStateProducesUpgradeGuidanceNamingTheTargetVersion() {
        FindingFix fix = FindingFixAdvisor.forVulnerability(FixState.FIXED, "2.17.1", FixSource.OSV, "log4j-core", "2.14.1");

        assertThat(fix.kind()).isEqualTo(FixKind.UPGRADE);
        assertThat(fix.fixedVersions()).isEqualTo("2.17.1");
        assertThat(fix.fixSource()).isEqualTo(FixSource.OSV);
        assertThat(fix.guidance()).contains("log4j-core").contains("2.14.1").contains("2.17.1");
    }

    @Test
    void fixedStateWithNullFixedVersionsStillProducesUpgradeGuidance() {
        FindingFix fix = FindingFixAdvisor.forVulnerability(FixState.FIXED, null, null, "log4j-core", "2.14.1");

        assertThat(fix.kind()).isEqualTo(FixKind.UPGRADE);
        assertThat(fix.fixedVersions()).isNull();
        assertThat(fix.guidance()).contains("a fixed version");
    }

    @Test
    void noFixStateProducesNoFixAvailableGuidance() {
        FindingFix fix = FindingFixAdvisor.forVulnerability(FixState.NO_FIX, null, null, "log4j-core", "2.14.1");

        assertThat(fix.kind()).isEqualTo(FixKind.NO_FIX_AVAILABLE);
        assertThat(fix.fixedVersions()).isNull();
        assertThat(fix.fixSource()).isNull();
        assertThat(fix.guidance()).contains("No fixed version");
    }

    @Test
    void unknownStateProducesUnknownGuidance() {
        FindingFix fix = FindingFixAdvisor.forVulnerability(FixState.UNKNOWN, null, null, "log4j-core", "2.14.1");

        assertThat(fix.kind()).isEqualTo(FixKind.UNKNOWN);
        assertThat(fix.guidance()).contains("No fix information");
    }

    @Test
    void nullFixStateAlsoProducesUnknown() {
        FindingFix fix = FindingFixAdvisor.forVulnerability(null, null, null, null, null);

        assertThat(fix.kind()).isEqualTo(FixKind.UNKNOWN);
        assertThat(fix.guidance()).contains("this component");
    }

    @Test
    void compromiseIsInvestigate() {
        assertThat(FindingFixAdvisor.forCompromise().kind()).isEqualTo(FixKind.INVESTIGATE_COMPROMISE);
    }

    @Test
    void lifecycleDriftIsReconcile() {
        assertThat(FindingFixAdvisor.forLifecycleDrift().kind()).isEqualTo(FixKind.RECONCILE_LIFECYCLE);
    }

    @Test
    void quantumVulnerableIsMigrateCrypto() {
        assertThat(FindingFixAdvisor.forQuantumVulnerable().kind()).isEqualTo(FixKind.MIGRATE_CRYPTO);
    }

    @Test
    void sbomQualityIsImproveSbom() {
        assertThat(FindingFixAdvisor.forSbomQuality().kind()).isEqualTo(FixKind.IMPROVE_SBOM);
    }

}
