package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.auth.dto.ErrorResponse;
import net.jdesive.secy.model.settings.ProductTaggingSettingsRequest;
import net.jdesive.secy.model.settings.ProductTaggingSettingsResponse;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.service.InvalidProductTagException;
import net.jdesive.secy.service.ProductTaggingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Tag(name = "Settings", description = "Per-tenant configuration — the product tag key (M1a)")
@RestController
@RequestMapping("settings/product-tagging")
@RequiredArgsConstructor
public class ProductTaggingSettingsController {

    private final ProductTaggingService productTaggingService;

    @Operation(summary = "Get the tenant's configured product tag key (default secy:product)")
    @GetMapping
    public ResponseEntity<ProductTaggingSettingsResponse> get() {
        // TODO(tenancy-hardening): request-scoped tenant, not the hardcoded default.
        String tagKey = productTaggingService.getTagKey(Tenant.DEFAULT_TENANT_ID);
        return ResponseEntity.ok(ProductTaggingSettingsResponse.of(tagKey));
    }

    @Operation(summary = "Set the tenant's product tag key",
            description = "Forward-only: changing the key never re-resolves SBOMs or products already ingested.")
    @PutMapping
    public ResponseEntity<ProductTaggingSettingsResponse> put(@RequestBody ProductTaggingSettingsRequest request) {
        // TODO(tenancy-hardening): request-scoped tenant, not the hardcoded default.
        String tagKey = productTaggingService.setTagKey(Tenant.DEFAULT_TENANT_ID, request.tagKey()).getTagKey();
        return ResponseEntity.ok(ProductTaggingSettingsResponse.of(tagKey));
    }

    @ExceptionHandler(InvalidProductTagException.class)
    public ResponseEntity<ErrorResponse> onInvalidTag(InvalidProductTagException e) {
        log.warn("Rejected product-tagging settings change: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }
}
