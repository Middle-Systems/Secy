package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.service.SourceConnectorService;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.UUID;

/**
 * Phase 6b's connectors view: where Secy should look for inventory on its own, and the sync job
 * that pulls it — GitHub only for this pass (ROADMAP.md's "Source & cloud connectors").
 *
 * <p>{@code POST}/{@code GET}/{@code DELETE} take and return {@link SourceConnector} directly, the
 * same convention {@code ProductController} uses — this is a plain CRUD resource, not a document
 * upload that needs synchronous validation before a job is queued.
 */
@Slf4j
@Tag(name = "Connectors", description = "Source/cloud connectors that sync their own inventory — GitHub repos and their dependency-graph SBOMs, agentless")
@RestController
@RequestMapping("connectors")
@RequiredArgsConstructor
public class SourceConnectorController {

    private final SourceConnectorService sourceConnectorService;
    private final JobService jobService;

    @Operation(summary = "Register a connector",
            description = "Does not trigger a sync — call POST /connectors/{id}/sync for that. "
                    + "`type` is GITHUB (the only value for this pass), `scope` is the GitHub org or "
                    + "user login to enumerate repos under, and `repoAllowlist` is optional: when set, "
                    + "only those `owner/repo` names are synced; when empty, every repo the token can "
                    + "see under `scope` is synced.")
    @PostMapping
    public ResponseEntity<SourceConnector> create(@RequestBody SourceConnector connector) {
        SourceConnector created = sourceConnectorService.create(connector);
        log.info("Created {} connector {} ({}) scoped to {}", created.getType(), created.getId(),
                created.getName(), created.getScope());
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @Operation(summary = "List connectors, newest first",
            description = "Spring `Page` shape (`content`, `totalElements`, `totalPages`, 0-indexed). "
                    + "Each row carries its own `status`/`lastSyncedAt` from its most recent sync.")
    @GetMapping
    public Page<SourceConnector> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return sourceConnectorService.list(page, size);
    }

    @Operation(summary = "One connector")
    @ApiResponse(responseCode = "404", description = "No connector with that id")
    @GetMapping("/{id}")
    public ResponseEntity<SourceConnector> detail(@PathVariable UUID id) {
        return sourceConnectorService.get(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "Sync a connector now",
            description = "Returns immediately with a QUEUED CONNECTOR_SYNC job; poll GET /jobs/{id} "
                    + "for progress. Mirrors POST /assets/scan/{scanner} and "
                    + "POST /compliance/reports/{id}/scan: one POST, one job. Repos are enumerated and "
                    + "their dependency-graph SBOMs pulled live during the job, not at request time, so "
                    + "this call never itself talks to GitHub.")
    @ApiResponse(responseCode = "202", description = "Sync queued")
    @ApiResponse(responseCode = "404", description = "No connector with that id")
    @PostMapping("/{id}/sync")
    public ResponseEntity<Job> sync(@PathVariable UUID id, Principal principal) {
        // Checked before creating the job — an unknown id must not leave an orphan QUEUED job with
        // nothing to process, mirroring ComplianceController#rescan.
        if (!sourceConnectorService.exists(id)) {
            return ResponseEntity.notFound().build();
        }
        Job job = jobService.create(JobType.CONNECTOR_SYNC, principal);
        return sourceConnectorService.queueSync(id, job.getId())
                .map(connector -> new ResponseEntity<>(job, HttpStatus.ACCEPTED))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "Delete a connector",
            description = "Removes the connector row only. Does NOT delete the Products/SBOMs it "
                    + "created — those are real inventory now, independent of whichever connector "
                    + "introduced them, exactly like a manually-uploaded SBOM outlives the request "
                    + "that uploaded it.")
    @ApiResponse(responseCode = "404", description = "No connector with that id")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        return sourceConnectorService.delete(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

}
