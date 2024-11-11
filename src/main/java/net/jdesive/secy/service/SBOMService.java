package net.jdesive.secy.service;

import net.jdesive.secy.model.cyclonedx.*;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class SBOMService {

    private final SBOMRepository sbomRepository;

    @Autowired
    public SBOMService(SBOMRepository sbomRepository) {
        this.sbomRepository = sbomRepository;
    }

    @Transactional
    public void ingestCycloneDX(CycloneDXFile cycloneDXFile) {
        SBOM sbom = new SBOM();
        sbom.setFormat(cycloneDXFile.getBomFormat());
        sbom.setVersion(cycloneDXFile.getVersion());
        sbom.setSpecVersion(cycloneDXFile.getSpecVersion());

        if (cycloneDXFile.getMetadata().getTools() != null) {
            for (CycloneDXTool cdxTool : cycloneDXFile.getMetadata().getTools()) {
                SBOMTool sbomTool = new SBOMTool();
                sbomTool.setName(cdxTool.getName());
                sbomTool.setVersion(cdxTool.getVersion());
                sbomTool.setVendor(cdxTool.getVendor());
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

        this.sbomRepository.save(sbom);
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

    public SBOM getSbomById(String sbomId) {
        Optional<SBOM> sbomOptional = this.sbomRepository.findById(sbomId);
        if (!sbomOptional.isPresent()) {
            throw new RuntimeException("Error finding sbom with id " + sbomId);
        }
        return sbomOptional.get();
    }
}
