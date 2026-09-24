package net.jdesive.secy.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;

@Slf4j
@Service
public class KEVService {

    /** Both the chunk size for batched writes and how often progress/cancellation are checked. */
    private static final int PROGRESS_EVERY = 250;

    private final KEVRepository kevRepository;

    private final RestTemplate restTemplate;

    /**
     * A programmatic transaction per chunk, not {@code @Transactional} on a same-class method — the
     * latter is a no-op here, since {@code ingest} would be calling it through {@code this}, which
     * bypasses the Spring AOP proxy that annotation relies on. This is also why each chunk gets its
     * own transaction rather than the whole ingest getting one: a run cancelled partway should keep
     * whatever chunks already committed rather than rolling all of them back, the same "partial
     * progress survives an interruption" property one-row-at-a-time {@code save()} calls had before,
     * just batched instead of one commit per row.
     */
    private final TransactionTemplate transactionTemplate;

    @PersistenceContext
    private EntityManager entityManager;

    private final String apiUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    @Autowired
    public KEVService(KEVRepository kevRepository, RestTemplate restTemplate,
                       PlatformTransactionManager transactionManager) {
        this.kevRepository = kevRepository;
        this.restTemplate = restTemplate;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
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
     * <p>{@code itemsProcessed} (here and in each {@link JobProgress#report}) counts rows actually
     * <b>written</b>, not merely considered — an entry identical to what's already stored (CISA
     * republishes its whole catalog on every pull; most entries never change day to day) is skipped
     * entirely by {@link #saveKevChunk}, the same way {@code NVDService}/{@code EPSSService} avoid a
     * pointless write. Safe here in a way it would not be for EPSS: every field compared is CISA's
     * own historical data (when *they* added the CVE, their own prose), not a "last seen by us"
     * timestamp anything else depends on for freshness.
     *
     * @throws CancellationException if {@code progress} asks to stop between chunks
     */
    public IngestResult ingest(JobProgress progress) {
        KevResponse response = restTemplate.getForObject(this.apiUrl, KevResponse.class);

        if (response == null || response.getVulnerabilities() == null || response.getVulnerabilities().isEmpty()) {
            return new IngestResult(0, "CISA returned an empty KEV catalog");
        }

        List<KevResponseVulnerability> all = response.getVulnerabilities();
        int processed = 0;

        for (int chunkStart = 0; chunkStart < all.size(); chunkStart += PROGRESS_EVERY) {
            List<KevResponseVulnerability> chunk =
                    all.subList(chunkStart, Math.min(chunkStart + PROGRESS_EVERY, all.size()));

            processed += transactionTemplate.execute(status -> saveKevChunk(chunk));
            progress.report(processed, "Ingested " + processed + " KEV entries…");

            boolean moreChunksRemain = chunkStart + PROGRESS_EVERY < all.size();
            if (moreChunksRemain && progress.isCancelled()) {
                throw new CancellationException("KEV ingest cancelled after " + processed + " entries");
            }
        }

        return IngestResult.of(processed, "KEV entries");
    }

    /** @return how many of {@code chunk} were actually new or changed and so written */
    private int saveKevChunk(List<KevResponseVulnerability> chunk) {
        List<String> ids = chunk.stream().map(KevResponseVulnerability::getCveId).toList();
        Map<String, KEV> existing = new HashMap<>();
        for (KEV k : kevRepository.findAllById(ids)) {
            existing.put(k.getCveId(), k);
        }

        int written = 0;
        for (KevResponseVulnerability vulnerability : chunk) {
            KEV existingRow = existing.get(vulnerability.getCveId());
            LocalDateTime added =
                    LocalDateTime.ofInstant(vulnerability.getDateAdded().toInstant(), ZoneId.systemDefault());

            if (existingRow != null && isUnchanged(existingRow, vulnerability, added)) {
                continue;
            }

            KEV kev = existingRow != null ? existingRow : new KEV();
            kev.setCveId(vulnerability.getCveId());
            kev.setName(vulnerability.getVulnerabilityName());
            kev.setDescription(vulnerability.getShortDescription());
            kev.setAdded(added);
            kev.setNotes(vulnerability.getNotes());
            kev.setProduct(vulnerability.getProduct());
            kev.setVendor(vulnerability.getVendorProject());
            kev.setDueDate(vulnerability.getDueDate());
            kev.setRequiredActions(vulnerability.getRequiredAction());
            kev.setKnownRansomwareCampaignUse(vulnerability.getKnownRansomwareCampaignUse());

            // See NVDService#saveVulnerabilities for why persist() rather than save()/saveAll()
            // matters here: KEV's @Id is manually assigned, so save() on a row Hibernate has never
            // seen would run a SELECT before it could decide INSERT vs UPDATE.
            if (existingRow == null) {
                entityManager.persist(kev);
            }
            written++;
        }
        return written;
    }

    private static boolean isUnchanged(KEV existing, KevResponseVulnerability incoming, LocalDateTime added) {
        return Objects.equals(existing.getVendor(), incoming.getVendorProject())
                && Objects.equals(existing.getProduct(), incoming.getProduct())
                && Objects.equals(existing.getName(), incoming.getVulnerabilityName())
                && Objects.equals(existing.getAdded(), added)
                && Objects.equals(existing.getDescription(), incoming.getShortDescription())
                && Objects.equals(existing.getRequiredActions(), incoming.getRequiredAction())
                && sameInstant(existing.getDueDate(), incoming.getDueDate())
                && Objects.equals(existing.getKnownRansomwareCampaignUse(), incoming.getKnownRansomwareCampaignUse())
                && Objects.equals(existing.getNotes(), incoming.getNotes());
    }

    /**
     * {@code dueDate} round-trips through JDBC as a {@link java.sql.Timestamp}, not the plain
     * {@link Date} the CISA feed deserializes into — and {@code Timestamp.equals(Object)} is
     * famously asymmetric, returning {@code false} for any object that isn't itself a
     * {@code Timestamp} even when it names the identical instant (see its own Javadoc). Comparing by
     * {@link Date#getTime()} instead sidesteps the concrete subtype entirely.
     */
    private static boolean sameInstant(Date a, Date b) {
        if (a == null || b == null) {
            return a == b;
        }
        return a.getTime() == b.getTime();
    }

}
