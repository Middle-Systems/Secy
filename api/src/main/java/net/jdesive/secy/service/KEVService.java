package net.jdesive.secy.service;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.kev.KevResponse;
import net.jdesive.secy.model.kev.KevResponseVulnerability;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.entity.KEV;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.concurrent.CancellationException;

@Slf4j
@Service
public class KEVService {

    /** Report progress (and check for cancellation) every this many saved entries. */
    private static final int PROGRESS_EVERY = 250;

    private final KEVRepository kevRepository;

    private final RestTemplate restTemplate;

    private final String apiUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    @Autowired
    public KEVService(KEVRepository kevRepository, RestTemplate restTemplate) {
        this.kevRepository = kevRepository;
        this.restTemplate = restTemplate;
    }

    public Page<KEV> getPagedKev(int page, int size, String search) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("added").descending());
        if (search == null || search.isEmpty()) {
            return kevRepository.findAll(pageable);
        }
        return kevRepository.searchKev(search, pageable);
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingest() {
        return ingest(JobProgress.NOOP);
    }

    /**
     * Pull the CISA KEV catalog, reporting the running count to {@code progress} so the ingestion
     * job row can show it while the run is still going.
     *
     * @throws CancellationException if {@code progress} asks to stop between batches
     */
    public IngestResult ingest(JobProgress progress) {
        KevResponse response = restTemplate.getForObject(this.apiUrl, KevResponse.class);

        if (response == null || response.getVulnerabilities() == null || response.getVulnerabilities().isEmpty()) {
            return new IngestResult(0, "CISA returned an empty KEV catalog");
        }

        int processed = 0;
        for (KevResponseVulnerability vulnerability : response.getVulnerabilities()) {
            KEV kev = new KEV();
            kev.setCveId(vulnerability.getCveId());
            kev.setName(vulnerability.getVulnerabilityName());
            kev.setDescription(vulnerability.getShortDescription());
            kev.setAdded(LocalDateTime.ofInstant(vulnerability.getDateAdded().toInstant(), ZoneId.systemDefault()));
            kev.setNotes(vulnerability.getNotes());
            kev.setProduct(vulnerability.getProduct());
            kev.setVendor(vulnerability.getVendorProject());
            kev.setDueDate(vulnerability.getDueDate());
            kev.setRequiredActions(vulnerability.getRequiredAction());
            kev.setKnownRansomwareCampaignUse(vulnerability.getKnownRansomwareCampaignUse());
            this.kevRepository.save(kev);
            processed++;

            if (processed % PROGRESS_EVERY == 0) {
                progress.report(processed, "Ingested " + processed + " KEV entries…");
                if (progress.isCancelled()) {
                    throw new CancellationException("KEV ingest cancelled after " + processed + " entries");
                }
            }
        }

        progress.report(processed, "Ingested " + processed + " KEV entries");
        return IngestResult.of(processed, "KEV entries");
    }

}
