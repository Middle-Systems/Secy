package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SBOMRepository extends JpaRepository<SBOM, UUID> {

    // Used to find the current 'Truth' for a product to deactivate it
    Optional<SBOM> findByProductIdAndActiveTrue(UUID productId);

    // Alternative if you prefer passing the Object
    List<SBOM> findByProductAndActiveTrue(Product product);

    // Useful for the UI to show history
    List<SBOM> findByProductIdOrderByUploadDateDesc(UUID productId);

    @Query("SELECT s FROM SBOM s LEFT JOIN FETCH s.components WHERE s.id = :id")
    Optional<SBOM> findByIdWithComponents(@Param("id") UUID id);

}
