package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse;
import net.jdesive.secy.service.metrics.LeadershipMetricsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/**
 * The M1k leadership view's one endpoint (ROADMAP.md — "Role-based views" §5). Aggregates only, no
 * finding rows — see {@code LeadershipMetricsResponse}'s Javadoc for exactly how each field's
 * population is built to agree with an existing, already-pinned endpoint by construction. No role
 * gating — any authenticated user may call this, same as every other M1k view.
 */
@Tag(name = "Leadership metrics", description = "M1k read-only posture aggregates for the leadership view")
@RestController
@RequestMapping("/metrics")
@RequiredArgsConstructor
public class LeadershipMetricsController {

    private final LeadershipMetricsService leadershipMetricsService;

    @Operation(summary = "Aggregate security-posture metrics for the leadership view",
            description = "No row-level drill-down -- only ids for links. mttrWindowDays defaults to 90.")
    @GetMapping("/leadership")
    public LeadershipMetricsResponse leadership(
            @Parameter(description = "1-3650") @RequestParam(defaultValue = "90") int mttrWindowDays) {
        if (mttrWindowDays < 1 || mttrWindowDays > 3650) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "mttrWindowDays must be between 1 and 3650");
        }
        return leadershipMetricsService.build(mttrWindowDays);
    }

}
