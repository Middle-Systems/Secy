package net.jdesive.secy.service;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.epss.EPSSData;
import net.jdesive.secy.model.epss.EPSSResponse;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.entity.EPSS;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;

@Slf4j
@Service
public class EPSSService {

    private final String apiUrl = "https://api.first.org/data/v1/epss";

    private final int resultsPerPage = 2000;

    private final EPSSRepository epssRepository;

    private final RestTemplate restTemplate;

    @Autowired
    public EPSSService(EPSSRepository epssRepository, RestTemplate restTemplate) {
        this.epssRepository = epssRepository;
        this.restTemplate = restTemplate;
    }

    public Page<EPSS> getPagedEpss(int page, int size, String search) {
        // Default to sorting by highest probability
        Pageable pageable = PageRequest.of(page, size, Sort.by("epss").descending());

        if (search == null || search.isEmpty()) {
            return epssRepository.findAll(pageable);
        }
        return epssRepository.searchEpss(search, pageable);
    }

    /** Ingest with nothing watching. Kept so any non-job caller still works. */
    public IngestResult ingestEPSSData() {
        return ingestEPSSData(JobProgress.NOOP);
    }

    /**
     * Pull every EPSS page from FIRST, reporting the running count to {@code progress} after each
     * one so the ingestion job row moves while the run is going.
     *
     * @throws CancellationException if {@code progress} asks to stop between pages
     */
    public IngestResult ingestEPSSData(JobProgress progress) {
        EPSSResponse result = this.getDataAtOffset(0);
        int total = result.getTotal();
        int offset = this.resultsPerPage;
        int processed = this.saveEPSS(result);
        progress.report(processed, "Ingested " + processed + " of " + total + " EPSS scores…");

        while(offset < total) {
            if (progress.isCancelled()) {
                throw new CancellationException("EPSS ingest cancelled after " + processed + " scores");
            }
            EPSSResponse nestedResult = this.getDataAtOffset(offset);
            offset = this.resultsPerPage + offset;
            processed += this.saveEPSS(nestedResult);
            progress.report(processed, "Ingested " + processed + " of " + total + " EPSS scores…");
        }

        return IngestResult.of(processed, "EPSS scores");
    }

    /** @return how many scores were written */
    public int saveEPSS(EPSSResponse response) {
        List<EPSS> epsses = new ArrayList<>();
        for (EPSSData epssData : response.getData()) {
            EPSS epss = new EPSS();
            epss.setCve(epssData.getCve());
            epss.setEpss(epssData.getEpss());
            epss.setPercentile(epssData.getPercentile());
            epss.setDate(LocalDateTime.ofInstant(epssData.getDate().toInstant(), ZoneId.systemDefault()));
            epsses.add(epss);
        }
        this.epssRepository.saveAll(epsses);
        return epsses.size();
    }

    private EPSSResponse getDataAtOffset(int offset) {

        log.debug("Fetching EPSS Vulnerability data from offset {}", offset);

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        String urlTemplate = UriComponentsBuilder.fromHttpUrl(this.apiUrl)
                .queryParam("limit", this.resultsPerPage)
                .queryParam("offset", offset)
                .encode()
                .toUriString();

        ResponseEntity<EPSSResponse> result = this.restTemplate.exchange(urlTemplate, HttpMethod.GET, entity, EPSSResponse.class);

        if (!result.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Error processing EPSS Data. API returned non success status code. [" + result.getStatusCode().value() + "]");
        }

        return result.getBody();
    }

}
