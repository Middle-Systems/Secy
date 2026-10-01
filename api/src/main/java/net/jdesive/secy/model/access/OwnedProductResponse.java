package net.jdesive.secy.model.access;

import java.util.UUID;

/** One row of {@code GET /me/owned-products} (M1k). */
public record OwnedProductResponse(UUID productId, String productName) {
}
