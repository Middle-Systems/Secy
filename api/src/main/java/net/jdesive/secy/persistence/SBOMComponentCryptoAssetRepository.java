package net.jdesive.secy.persistence;

import net.jdesive.secy.model.cbom.VulnerableCryptoRow;
import net.jdesive.secy.persistence.entity.SBOMComponentCryptoAsset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface SBOMComponentCryptoAssetRepository
        extends JpaRepository<SBOMComponentCryptoAsset, UUID>, JpaSpecificationExecutor<SBOMComponentCryptoAsset> {

    /**
     * Every {@code VULNERABLE} crypto asset row across a set of SBOMs — the reconciliation read for
     * {@code QuantumFindingService.reconcileForSbom} (M1g), the crypto-finding twin of
     * {@code SBOMComponentRepository.findStageComponents}.
     */
    @Query("""
            select new net.jdesive.secy.model.cbom.VulnerableCryptoRow(a.id, c.id, s.id, a.cryptoIdentityKey,
                   a.assetType, c.name, c.bomRef, a.quantumFamily, a.quantumBasis, a.quantumIndicator,
                   a.nistQuantumSecurityLevel, a.primitive)
            from SBOMComponentCryptoAsset a join a.component c join c.sbom s
            where s.id in :sbomIds and a.quantumStatus = net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus.VULNERABLE
              and a.cryptoIdentityKey is not null
            """)
    List<VulnerableCryptoRow> findVulnerableInSboms(@Param("sbomIds") Collection<UUID> sbomIds);

}
