package net.jdesive.secy.service;

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

@Service
public class KEVService {

    private final KEVRepository kevRepository;

    private final String apiUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    @Autowired
    public KEVService(KEVRepository kevRepository) {
        this.kevRepository = kevRepository;
    }

    public Page<KEV> getPagedKev(int page, int size, String search) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("added").descending());
        if (search == null || search.isEmpty()) {
            return kevRepository.findAll(pageable);
        }
        return kevRepository.searchKev(search, pageable);
    }

    public void ingest() {
        RestTemplate template = new RestTemplate();
        KevResponse response = template.getForObject(this.apiUrl, KevResponse.class);

        if (response == null || response.getVulnerabilities() == null || response.getVulnerabilities().isEmpty()) {
            return;
        }

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
        }
    }

}
