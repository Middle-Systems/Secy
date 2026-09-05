package net.jdesive.secy.service;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.entity.CPEMatch;
import net.jdesive.secy.persistence.entity.CPEOperator;
import net.jdesive.secy.persistence.entity.Reference;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.nvd.*;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;

@Slf4j
@Service
public class NVDService {

    private VulnerabilityRepository vulnerabilityRepository;

    private final RestTemplate restTemplate;

    @Autowired
    public NVDService(VulnerabilityRepository vulnerabilityRepository, RestTemplate restTemplate) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.restTemplate = restTemplate;
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

    public Page<Vulnerability> findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(String search, int page, int size) {
        return vulnerabilityRepository.findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                search, search, PageRequest.of(page, size));
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingestData() {
        return ingestData(JobProgress.NOOP);
    }

    /**
     * Pull every CVE page from the NVD 2.0 feed, reporting the running count to {@code progress}
     * after each page — this is the long one, so the job row needs to move.
     *
     * @throws CancellationException if {@code progress} asks to stop between pages
     */
    public IngestResult ingestData(JobProgress progress) {

       NVDCVEResult result = this.getDataAtOffset(0);
       int processed = this.saveVulnerabilities(result);
       int total = result.getTotalResults();
       int offset = this.resultsPerPage;
       progress.report(processed, "Ingested " + processed + " of " + total + " CVE records…");

       while(offset < total) {

           if (progress.isCancelled()) {
               throw new CancellationException("NVD ingest cancelled after " + processed + " records");
           }

           NVDCVEResult nestedResult = this.getDataAtOffset(offset);
           offset = this.resultsPerPage + offset;
           processed += this.saveVulnerabilities(nestedResult);
           progress.report(processed, "Ingested " + processed + " of " + total + " CVE records…");
       }

       return IngestResult.of(processed, "CVE records");
    }

    /** @return how many vulnerabilities were written */
    @Transactional
    public int saveVulnerabilities(NVDCVEResult result) {

        List<Vulnerability> vulns = new ArrayList<>();
        for (NVDVulnerability nvdVulnerability : result.getVulnerabilities()) {

            Optional<NVDCVEDescription> descriptionOptional = nvdVulnerability.getCve().getDescriptions().stream().filter(desc -> Objects.equals(desc.getLang(), "en")).findFirst();
            String description = "N/A";

            if (descriptionOptional.isPresent()) {
                description = descriptionOptional.get().getValue();
            }

            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setId(nvdVulnerability.getCve().getId());
            vulnerability.setPublished(LocalDateTime.ofInstant(nvdVulnerability.getCve().getPublished().toInstant(), ZoneId.systemDefault()));
            vulnerability.setLastModified(LocalDateTime.ofInstant(nvdVulnerability.getCve().getLastModified().toInstant(), ZoneId.systemDefault()));
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
        return vulns.size();
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

        ResponseEntity<NVDCVEResult> result = this.restTemplate.exchange(urlTemplate, HttpMethod.GET, entity, NVDCVEResult.class);

        if (!result.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Error processing NVD Data. API returned non success status code. [" + result.getStatusCode().value() + "]");
        }

        return result.getBody();
    }

}
