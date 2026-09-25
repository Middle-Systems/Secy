package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.lineage.LineageRebuildService;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * M1d's lineage-graph rebuild trigger. No graph-read endpoint exists yet — this milestone only
 * ships the rebuild-on-demand write path (ROADMAP.md, M1d).
 */
@Tag(name = "Lineage", description = "Apache AGE lineage graph rebuild (M1d)")
@RestController
@RequestMapping("lineage")
@RequiredArgsConstructor
public class LineageController {

    private final LineageRebuildService lineageRebuildService;

    private final JobService jobService;

    // TODO(M1k/tenancy-hardening): gate this to tenant admins once role-based access exists —
    // today every authenticated user can trigger a rebuild, same as every other ingest endpoint.
    @Operation(
            summary = "Queue a full lineage-graph rebuild",
            description = "Rebuilds every tenant's Apache AGE lineage graph from Postgres. 503 when "
                    + "secy.lineage.enabled=false or no graph writer is configured — most commonly a "
                    + "Postgres without the AGE extension installed.")
    @ApiResponse(responseCode = "202", description = "Rebuild queued (or already in flight)")
    @ApiResponse(responseCode = "503", description = "Lineage graph is not enabled on this instance")
    @PostMapping("/rebuild")
    public ResponseEntity<?> rebuild(Principal principal) {
        if (!lineageRebuildService.isAvailable()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ErrorResponse("Lineage graph is not enabled on this instance."));
        }
        return ResponseEntity.accepted().body(jobService.enqueue(JobType.LINEAGE_REBUILD, principal));
    }

}
