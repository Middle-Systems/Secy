package net.jdesive.secy.model.actionitem;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import net.jdesive.secy.model.finding.FindingRef;

import java.util.List;
import java.util.UUID;

/** Body of {@code POST /action-items}. */
public record CreateActionItemRequest(
        @NotBlank(message = "title is required")
        @Size(max = 255, message = "title must be at most 255 characters")
        String title,

        @Size(max = 4096, message = "description must be at most 4096 characters")
        String description,

        UUID assigneeUserId,

        @NotEmpty(message = "findings must not be empty")
        @Valid
        List<FindingRef> findings) {
}
