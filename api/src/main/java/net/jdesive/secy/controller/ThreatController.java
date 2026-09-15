package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.MaliciousPackage;
import net.jdesive.secy.persistence.entity.MalwareHash;
import net.jdesive.secy.service.MaliciousPackageIngestService;
import net.jdesive.secy.service.MalwareHashIngestService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

/**
 * The two Phase 6 threat feeds: ingest triggers and a browse view of each corpus.
 *
 * <h2>Why two ingest endpoints under one path, and not one {@code POST /threat/ingest}</h2>
 *
 * <p>The roadmap wrote it as a single {@code POST /threat/ingest}. Split, because the two feeds have
 * nothing in common operationally: one is a ~310 MB GitHub archive that takes minutes, the other a
 * ~380 KB CSV that takes a second (or a ~220 MB zip, if pointed at the full corpus). They fail
 * independently, are rate-limited independently, and — the deciding factor — the job queue's
 * {@code uq_ingestion_job_active_type} constraint is per {@link JobType}, so one endpoint enqueuing
 * one job would have forced them to share a type and therefore a slot: a running malicious-packages
 * pull would block a malware-hash refresh for no reason. Two types, two endpoints, two independent
 * progress bars. {@code POST /threat/ingest} is kept as a convenience that enqueues both and returns
 * both jobs.
 *
 * <p>All three return {@code 202} with the {@code QUEUED} job(s); poll {@code GET /jobs/{id}} for
 * progress. As with every other feed, only one ingestion per type runs at a time — if one is already
 * queued or running, that job is returned instead of a new one.
 */
@Tag(name = "Threat",
        description = "Supply-chain threat feeds: OpenSSF Malicious Packages and abuse.ch MalwareBazaar")
@RestController
@RequestMapping("/threat")
@RequiredArgsConstructor
public class ThreatController {

    private final MaliciousPackageIngestService maliciousPackageIngestService;

    private final MalwareHashIngestService malwareHashIngestService;

    private final JobService jobService;

    /* ------------------------------------------------------------------ */
    /* Ingest                                                             */
    /* ------------------------------------------------------------------ */

    @Operation(
            summary = "Queue both threat-feed ingests",
            description = "Convenience wrapper: enqueues MALICIOUS_PACKAGES and MALWARE_HASHES and "
                    + "returns both jobs, in that order. The two run independently — one failing does "
                    + "not affect the other.")
    @ApiResponse(responseCode = "202", description = "Both ingestions queued (or already in flight)")
    @PostMapping("/ingest")
    public ResponseEntity<List<Job>> ingestAll(Principal principal) {
        return ResponseEntity.accepted().body(List.of(
                jobService.enqueue(JobType.MALICIOUS_PACKAGES, principal),
                jobService.enqueue(JobType.MALWARE_HASHES, principal)));
    }

    @Operation(
            summary = "Queue a mirror of the OpenSSF Malicious Packages corpus",
            description = "Pulls the ossf/malicious-packages repository archive (~310 MB) and upserts "
                    + "every MAL- record in the configured ecosystems. A full refresh, not incremental: "
                    + "a repository archive carries no per-record high-water mark to resume from.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("/ingest/malicious-packages")
    public ResponseEntity<Job> ingestMaliciousPackages(Principal principal) {
        return ResponseEntity.accepted().body(jobService.enqueue(JobType.MALICIOUS_PACKAGES, principal));
    }

    @Operation(
            summary = "Queue a mirror of the abuse.ch MalwareBazaar hash corpus",
            description = "Pulls the configured CSV export (the public keyless one by default) and "
                    + "upserts every sample by SHA-256. Point secy.compromise.malware-bazaar-url at "
                    + "/export/csv/full/ for the whole corpus; zipped payloads are unpacked "
                    + "automatically.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("/ingest/malware-hashes")
    public ResponseEntity<Job> ingestMalwareHashes(Principal principal) {
        return ResponseEntity.accepted().body(jobService.enqueue(JobType.MALWARE_HASHES, principal));
    }

    /* ------------------------------------------------------------------ */
    /* Browse                                                             */
    /* ------------------------------------------------------------------ */

    @Operation(summary = "Browse the malicious-package mirror, optionally filtered by ecosystem and name")
    @GetMapping("/malicious-packages")
    public Page<MaliciousPackage> maliciousPackages(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Exact OSV ecosystem name, case-insensitive (npm, PyPI, Maven, …)")
            @RequestParam(required = false) String ecosystem,
            @Parameter(description = "Substring of the package name, case-insensitive")
            @RequestParam(required = false) String packageName) {
        return maliciousPackageIngestService.getPaged(ecosystem, packageName, page, size);
    }

    @Operation(summary = "Browse the malware-hash corpus, optionally filtered by malware family")
    @GetMapping("/malware-hashes")
    public Page<MalwareHash> malwareHashes(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Substring of the abuse.ch signature / malware family, case-insensitive")
            @RequestParam(required = false) String signature) {
        return malwareHashIngestService.getPaged(signature, page, size);
    }

}
