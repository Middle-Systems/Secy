package net.jdesive.secy.service;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.entity.CPEMatch;
import net.jdesive.secy.persistence.entity.CPEOperator;
import net.jdesive.secy.persistence.entity.Reference;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.model.nvd.*;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Service
public class NVDService {

    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    public NVDService(VulnerabilityRepository vulnerabilityRepository) {
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    private final String cveApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private final int resultsPerPage = 2000;

    @Value("${nvd.apikey}")
    private String apiKey;

    public Vulnerability getVulnerabilityById(String id) {
        Optional<Vulnerability> optional = this.vulnerabilityRepository.findById(id);

        if (!optional.isPresent()) {
            throw new RuntimeException("Vulnerability with id [" + id + "] was not found");
        }

        return optional.get();
    }

    public void ingestData() {

       NVDCVEResult result = this.getDataAtOffset(0);
       this.saveVulnerabilities(result);
       int total = result.getTotalResults();
       int offset = this.resultsPerPage;

       while(offset < total) {

           NVDCVEResult nestedResult = this.getDataAtOffset(offset);
           offset = this.resultsPerPage + offset;
           this.saveVulnerabilities(nestedResult);
       }

    }

    @Transactional
    public void saveVulnerabilities(NVDCVEResult result) {

        List<Vulnerability> vulns = new ArrayList<>();
        for (NVDVulnerability nvdVulnerability : result.getVulnerabilities()) {

            Optional<NVDCVEDescription> descriptionOptional = nvdVulnerability.getCve().getDescriptions().stream().filter(desc -> Objects.equals(desc.getLang(), "en")).findFirst();
            String description = "N/A";

            if (descriptionOptional.isPresent()) {
                description = descriptionOptional.get().getValue();
            }

            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setId(nvdVulnerability.getCve().getId());
            vulnerability.setPublished(nvdVulnerability.getCve().getPublished());
            vulnerability.setLastModified(nvdVulnerability.getCve().getLastModified());
            vulnerability.setSourceIdentifier(nvdVulnerability.getCve().getSourceIdentifier());
            vulnerability.setDescription(description);
            vulnerability.setVulnStatus(nvdVulnerability.getCve().getVulnStatus());

            if (nvdVulnerability.getCve().getCveTags() != null) {
                StringBuilder cveTags = new StringBuilder();
                for (NVDCVETag nvdCveTag : nvdVulnerability.getCve().getCveTags()) {
                    cveTags.append(String.join(",", nvdCveTag.getTags()));
                }
                vulnerability.setCveTags(cveTags.toString());
            }

            if (nvdVulnerability.getCve().getReferences() != null) {
                for (NVDCVEReference nvdReference : nvdVulnerability.getCve().getReferences()) {
                    Reference reference = new Reference();
                    reference.setUrl(nvdReference.getUrl());
                    reference.setSource(nvdReference.getSource());
                    if (nvdReference.getTags() != null)
                        reference.setTags(String.join(",", nvdReference.getTags()));
                    reference.setCve(vulnerability);
                    vulnerability.getReferences().add(reference);
                }
            }

            if (nvdVulnerability.getCve().getWeaknesses() != null) {
                List<String> tags = new ArrayList<>();
                for (NVDCVEWeakness nvdcveWeakness : nvdVulnerability.getCve().getWeaknesses()) {
                    for (NVDCVEWeaknessDescription nvdcveWeaknessDescription : nvdcveWeakness.getDescription()) {
                        tags.add(nvdcveWeaknessDescription.getValue());
                    }
                }
                vulnerability.setCwe(String.join(",", tags));
            }

            // Grab the first metric TODO: Search for primary and ingest that
            if (nvdVulnerability.getCve().getMetrics().getCvssMetricV2() != null) {
                CVSSMetricV2 metrics = nvdVulnerability.getCve().getMetrics().getCvssMetricV2().get(0);
                vulnerability.setBaseSeverity(metrics.getBaseSeverity());
                vulnerability.setAccessVector(metrics.getCvssData().getAccessVector());
                vulnerability.setAccessComplexity(metrics.getCvssData().getAccessComplexity());
                vulnerability.setAuthenticationRequired(metrics.getCvssData().getAuthentication());
                vulnerability.setConfidentialityImpact(metrics.getCvssData().getConfidentialityImpact());
                vulnerability.setIntegrityImpact(metrics.getCvssData().getIntegrityImpact());
                vulnerability.setAvailabilityImpact(metrics.getCvssData().getAvailabilityImpact());
                vulnerability.setCvssScore(metrics.getCvssData().getBaseScore());
                vulnerability.setExploitabilityScore(metrics.getExploitabilityScore());
                vulnerability.setImpactScore(metrics.getImpactScore());
                vulnerability.setCanObtainAllPrivilege(metrics.isObtainAllPrivilege());
                vulnerability.setCanObtainUserPrivilege(metrics.isObtainUserPrivilege());
                vulnerability.setCanObtainOtherPrivilege(metrics.isObtainOtherPrivilege());
                vulnerability.setUserInteractionRequired(metrics.isUserInteractionRequired());
            }

            if (nvdVulnerability.getCve().getConfigurations() != null) {
                for (NVDCVEConfiguration nvdConfiguration : nvdVulnerability.getCve().getConfigurations()) {
                    for (NVDCVEConfigurationNode nvdNode : nvdConfiguration.getNodes()) {
                        CPEOperator cpeOperator = new CPEOperator();
                        cpeOperator.setOperator(nvdNode.getOperator());
                        cpeOperator.setNegate(nvdNode.isNegate());
                        cpeOperator.setCve(vulnerability);

                        for (NVDCVEConfigurationNodeCPEMatch nvdCpeMatch : nvdNode.getCpeMatch()) {
                            CPEMatch cpeMatch = new CPEMatch();
                            cpeMatch.setVulnerable(nvdCpeMatch.isVulnerable());
                            cpeMatch.setCriteria(nvdCpeMatch.getCriteria());
                            cpeMatch.setMatchCriteriaId(nvdCpeMatch.getMatchCriteriaId());
                            cpeMatch.setOperator(cpeOperator);

                            cpeOperator.getCpeMatches().add(cpeMatch);
                        }
                        vulnerability.getCpeOperators().add(cpeOperator);
                    }
                }
            }

            log.debug("Saving vuln {}", vulnerability);
            vulns.add(vulnerability);
        }
        this.vulnerabilityRepository.saveAll(vulns);
    }

    private NVDCVEResult getDataAtOffset(int offset) {

        log.debug("Fetching NVD Vulnerability data from offset {}", offset);

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + this.apiKey);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        String urlTemplate = UriComponentsBuilder.fromHttpUrl(this.cveApiUrl)
                .queryParam("resultsPerPage", this.resultsPerPage)
                .queryParam("startIndex", offset)
                .encode()
                .toUriString();

        RestTemplate template = new RestTemplate();

        ResponseEntity<NVDCVEResult> result = template.exchange(urlTemplate, HttpMethod.GET, entity, NVDCVEResult.class);

        if (!result.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Error processing NVD Data. API returned non success status code. [" + result.getStatusCode().value() + "]");
        }

        return result.getBody();
    }

}
