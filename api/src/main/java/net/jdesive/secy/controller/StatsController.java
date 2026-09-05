package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.model.DashboardStats;
import net.jdesive.secy.service.StatisticsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Stats", description = "Aggregate metrics powering the dashboard")
@RestController
@RequestMapping("/stats")
public class StatsController {

    @Autowired
    private StatisticsService statsService;

    @Operation(summary = "Dashboard roll-up: asset, vulnerability and actionable-alert counts")
    @GetMapping("/dashboard")
    public ResponseEntity<DashboardStats> getDashboard() {
        return ResponseEntity.ok(statsService.getDashboardMetrics());
    }
}