package net.jdesive.secy.service;

import net.jdesive.secy.events.SbomUploadedEvent;
import net.jdesive.secy.model.cyclonedx.*;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class SBOMService {

    private final SBOMRepository sbomRepository;
    private final VulnerabilityScanner scanner;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired
    public SBOMService(SBOMRepository sbomRepository, VulnerabilityScanner scanner, ApplicationEventPublisher eventPublisher) {
        this.sbomRepository = sbomRepository;
        this.scanner = scanner;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public SBOM ingestAndPrepare(Product product, CycloneDXFile cycloneDXFile, String productVersion) {
        // 1. Map and Link
        SBOM sbom = new SBOM();
        sbom.setFormat(cycloneDXFile.getBomFormat());
        sbom.setVersion(cycloneDXFile.getVersion());
        sbom.setSpecVersion(cycloneDXFile.getSpecVersion());
        sbom.setProductVersion(productVersion);

        if (cycloneDXFile.getMetadata().getTools() != null) {
            for (CycloneDXTool cdxTool : cycloneDXFile.getMetadata().getTools().getComponents()) {
                SBOMTool sbomTool = new SBOMTool();
                sbomTool.setName(cdxTool.getName());
                sbomTool.setVersion(cdxTool.getVersion());
                sbomTool.setGroup(cdxTool.getGroup());
                sbomTool.setType(cdxTool.getType());
                sbomTool.setSbom(sbom);
                sbom.getTools().add(sbomTool);
            }
        }

        sbom.setComponent(this.parseCdxComponent(cycloneDXFile.getMetadata().getComponent(), sbom));

        if (cycloneDXFile.getComponents() != null) {
            for (CycloneDXComponent cdxFileComponent : cycloneDXFile.getComponents()) {
                sbom.getComponents().add(this.parseCdxComponent(cdxFileComponent, sbom));
            }
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


    private SBOMComponent parseCdxComponent(CycloneDXComponent component, SBOM sbom) {
        SBOMComponent sbomComponent = new SBOMComponent();
        sbomComponent.setName(component.getName());
        sbomComponent.setDescription(component.getDescription());
        sbomComponent.setVersion(component.getVersion());
        sbomComponent.setType(component.getType());
        sbomComponent.setBomRef(component.getBomRef());
        sbomComponent.setPurl(component.getPurl());
        sbomComponent.setSbom(sbom);

        if (component.getLicenses() != null) {
            for (CycloneDXComponentLicense cdxLicense : component.getLicenses()) {
                SBOMLicense sbomLicense = new SBOMLicense();
                sbomLicense.setLicense(cdxLicense.getLicense().getId());
                sbomLicense.setComponent(sbomComponent);
                sbomComponent.getLicenses().add(sbomLicense);
            }
        }

        if (component.getExternalReferences() != null) {
            for (CycloneDXExternalReference cdxExternalReference : component.getExternalReferences()) {
                SBOMReference sbomReference = new SBOMReference();
                sbomReference.setType(cdxExternalReference.getType());
                sbomReference.setUrl(cdxExternalReference.getUrl());
                sbomReference.setComponent(sbomComponent);
                sbomComponent.getReferences().add(sbomReference);
            }
        }

        return sbomComponent;
    }

    public SBOM getSbomById(UUID sbomId) {
        Optional<SBOM> sbomOptional = this.sbomRepository.findById(sbomId);
        if (!sbomOptional.isPresent()) {
            throw new RuntimeException("Error finding sbom with id " + sbomId);
        }
        return sbomOptional.get();
    }
}
