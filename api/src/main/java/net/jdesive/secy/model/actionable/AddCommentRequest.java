package net.jdesive.secy.model.actionable;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of {@code POST /actionable/{id}/comments}. */
public record AddCommentRequest(

        @NotBlank(message = "comment is required")
        @Size(max = 4096, message = "comment must be at most 4096 characters")
        String comment) {
}
