package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.AssetComponent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AssetComponentRepository extends JpaRepository<AssetComponent, UUID> {

    /**
     * Every component row an asset has ever had, present or not.
     *
     * <p>The scan upserts against this set by {@code identityKey}: a package still reported keeps its
     * row (and therefore its alerts), one that has vanished is flipped to
     * {@code presentInLastScan = false} rather than deleted.
     */
    List<AssetComponent> findAllByAssetId(UUID assetId);

    List<AssetComponent> findAllByAssetIdAndPresentInLastScanTrue(UUID assetId);

}
