package net.jdesive.secy.model.component;

import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * The formal answer to "where did this component instance come from" (M1c, ROADMAP.md — "Canonical
 * component identity") — which SBOM, which product, which ingestion channel/job/connector, which
 * lifecycle stage, and the document's own internal handle for it. This is what M1d (lineage graph)
 * and M1e (lifecycle diffing) read once they exist; M1c only formalises the field.
 *
 * @param sbomId            the owning {@link SBOM}'s id
 * @param productId         the product the SBOM belongs to, or null (defensive — every SBOM has one in practice)
 * @param format             {@code sbom.format}
 * @param specVersion        {@code sbom.specVersion}
 * @param ingestedAt         {@code sbom.uploadDate}
 * @param ingestionSource    which entry point created the SBOM row, or null on a pre-M1c row
 * @param ingestionJobId     the job that ingested it ({@code sbom.jobId}), or null
 * @param sourceConnectorId  the {@code SourceConnector} that produced it, when applicable, or null
 * @param lifecycleStage     reserved for M1e; null until then
 * @param bomRef             the document's own internal handle for this component — provenance only, never identity
 */
public record ComponentProvenance(UUID sbomId, UUID productId, String format, String specVersion,
                                  LocalDateTime ingestedAt, SbomIngestionSource ingestionSource,
                                  UUID ingestionJobId, UUID sourceConnectorId,
                                  SbomLifecycleStage lifecycleStage, String bomRef) {

    /** Must be called inside a transaction — {@code component.getSbom()}/{@code sbom.getProduct()} are lazy. */
    public static ComponentProvenance of(SBOMComponent c) {
        SBOM sbom = c.getSbom();
        return new ComponentProvenance(
                sbom == null ? null : sbom.getId(),
                sbom == null || sbom.getProduct() == null ? null : sbom.getProduct().getId(),
                sbom == null ? null : sbom.getFormat(),
                sbom == null ? null : sbom.getSpecVersion(),
                sbom == null ? null : sbom.getUploadDate(),
                sbom == null ? null : sbom.getIngestionSource(),
                sbom == null ? null : sbom.getJobId(),
                sbom == null ? null : sbom.getSourceConnectorId(),
                sbom == null ? null : sbom.getLifecycleStage(),
                c.getBomRef());
    }

}
