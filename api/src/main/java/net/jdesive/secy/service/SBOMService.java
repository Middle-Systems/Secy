package net.jdesive.secy.service;

import net.jdesive.secy.events.SbomUploadedEvent;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Persists a parsed SBOM and kicks off its scan.
 *
 * <p>Takes a {@link NormalizedSbom} and nothing else — format detection and parsing happen upstream
 * in {@code SbomParser}, so this class is identical for CycloneDX and SPDX uploads and everything
 * downstream of it is too.
 *
 * <h2>Component rows are per-SBOM; component <em>identity</em> is per-product</h2>
 *
 * <p>Each upload still writes its own {@code sbom_component} rows. That is deliberate, not
 * leftover: an SBOM version is a snapshot of what the product shipped at that moment, and sharing
 * rows across versions would erase the very membership a history diff needs to read. What carries
 * across versions is {@link SBOMComponent#getIdentityKey()} — the version-less PURL — which is the
 * key {@code CorrelationService} upserts alerts on. So the same dependency in v1 and v2 has two rows
 * and one identity, and its alerts follow the identity.
 */
@Service
public class SBOMService {

    private final SBOMRepository sbomRepository;
    private final VulnerabilityScanner scanner;
    private final ApplicationEventPublisher eventPublisher;

    /** {@code sbom_component.description}. SPDX descriptions routinely run past this. */
    private static final int MAX_DESCRIPTION = 1024;

    /** {@code sbom_component.purl} / {@code sbom_license.license} / {@code sbom_reference.url}. */
    private static final int MAX_PURL = 512;
    private static final int MAX_SHORT_TEXT = 255;

    @Autowired
    public SBOMService(SBOMRepository sbomRepository, VulnerabilityScanner scanner, ApplicationEventPublisher eventPublisher) {
        this.sbomRepository = sbomRepository;
        this.scanner = scanner;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public SBOM ingestAndPrepare(Product product, NormalizedSbom document, String productVersion) {
        // 1. Map and Link
        SBOM sbom = new SBOM();
        sbom.setFormat(document.format().label());
        sbom.setVersion(document.version());
        sbom.setSpecVersion(truncate(document.specVersion(), MAX_SHORT_TEXT));
        sbom.setProductVersion(productVersion);

        for (NormalizedSbom.NormalizedTool tool : document.tools()) {
            SBOMTool sbomTool = new SBOMTool();
            sbomTool.setName(truncate(tool.name(), MAX_SHORT_TEXT));
            sbomTool.setVersion(truncate(tool.version(), MAX_SHORT_TEXT));
            sbomTool.setGroup(truncate(tool.group(), MAX_SHORT_TEXT));
            sbomTool.setType(truncate(tool.type(), MAX_SHORT_TEXT));
            sbomTool.setSbom(sbom);
            sbom.getTools().add(sbomTool);
        }

        if (document.rootComponent() != null) {
            sbom.setComponent(toEntity(document.rootComponent(), sbom));
        }

        for (NormalizedComponent component : document.components()) {
            sbom.getComponents().add(toEntity(component, sbom));
        }

        sbom.setProduct(product);

        // 2. Set Status (helpful for the UI to show 'Scanning...')
        sbom.setStatus("PROCESSING");
        sbom.setUploadDate(LocalDateTime.now());

        // 3. Versioning Logic: Deactivate previous versions
        deactivateOldSboms(product);
        sbom.setActive(true);

        // 4. Save to DB so we have an ID for the async task
        SBOM savedSbom = sbomRepository.saveAndFlush(sbom);

        // 5. Trigger Async Scan
        eventPublisher.publishEvent(new SbomUploadedEvent(savedSbom.getId()));

        return savedSbom;
    }

    private void deactivateOldSboms(Product product) {
        // Find current active SBOM for this product and set active = false
        sbomRepository.findByProductIdAndActiveTrue(product.getId())
                .ifPresent(old -> old.setActive(false));
    }

    /**
     * The single normalized-model → storage-model mapping. Both parsers land here and nothing else
     * writes an {@code SBOMComponent} on the upload path.
     *
     * <p>{@code identityKey} is not set here — {@link SBOMComponent#refreshIdentityKey()} derives it
     * on persist, so it is right for every writer, not just this one.
     */
    private SBOMComponent toEntity(NormalizedComponent component, SBOM sbom) {
        SBOMComponent entity = new SBOMComponent();
        entity.setName(truncate(component.name(), MAX_SHORT_TEXT));
        entity.setDescription(truncate(component.description(), MAX_DESCRIPTION));
        entity.setVersion(truncate(component.version(), MAX_SHORT_TEXT));
        entity.setType(truncate(component.type(), MAX_SHORT_TEXT));
        entity.setBomRef(truncate(component.bomRef(), MAX_SHORT_TEXT));
        entity.setPurl(truncate(component.purl(), MAX_PURL));
        entity.setSbom(sbom);

        for (String license : component.licenses()) {
            SBOMLicense sbomLicense = new SBOMLicense();
            sbomLicense.setLicense(truncate(license, MAX_SHORT_TEXT));
            sbomLicense.setComponent(entity);
            entity.getLicenses().add(sbomLicense);
        }

        for (NormalizedComponent.ExternalReference reference : component.externalReferences()) {
            SBOMReference sbomReference = new SBOMReference();
            sbomReference.setType(truncate(reference.type(), MAX_SHORT_TEXT));
            sbomReference.setUrl(truncate(reference.url(), MAX_SHORT_TEXT));
            sbomReference.setComponent(entity);
            entity.getReferences().add(sbomReference);
        }

        return entity;
    }

    /**
     * Ingest hardening: an over-long field truncates rather than failing the whole upload. A
     * description clipped at 1024 characters costs nothing; a rejected SBOM costs the user every
     * component in it.
     */
    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    public SBOM getSbomById(UUID sbomId) {
        Optional<SBOM> sbomOptional = this.sbomRepository.findById(sbomId);
        if (!sbomOptional.isPresent()) {
            throw new RuntimeException("Error finding sbom with id " + sbomId);
        }
        return sbomOptional.get();
    }
}
