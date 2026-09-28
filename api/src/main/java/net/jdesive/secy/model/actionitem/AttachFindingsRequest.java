package net.jdesive.secy.model.actionitem;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import net.jdesive.secy.model.finding.FindingRef;

import java.util.List;

/** Body of {@code POST /action-items/{id}/findings}. */
public record AttachFindingsRequest(
        @NotEmpty(message = "findings must not be empty")
        @Valid
        List<FindingRef> findings) {
}
