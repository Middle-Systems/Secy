package net.jdesive.secy.model.vex;

import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.util.UUID;

/**
 * {@code POST /vex/statements} body (M1k — ROADMAP.md's "Role-based views" §7/§9, "dispute with a
 * VEX justification"). A dispute IS one of these, authored on the caller's behalf by
 * {@code ActionItemDisputeService} — see that class and {@code VexAuthoringService}.
 *
 * @param cveId           must pass {@code VexParsing.cveIds} — exactly one recognisable CVE id
 * @param productId       optional — matches {@code POST /vex}'s unscoped option; unknown id is 404,
 *                        the Unassigned bucket is 400
 * @param purl            must resolve to a non-null {@code VexParsing.purlTarget(purl).matchKey()}
 * @param status          required
 * @param justification   required when {@code status == NOT_AFFECTED} unless {@link #impactStatement}
 *                        is non-blank — otherwise the statement would be a reasonless not-affected
 *                        claim and the parser would silently skip it
 * @param impactStatement optional (required for NOT_AFFECTED without a justification), ≤4096 chars
 * @param actionStatement optional, ≤4096 chars
 */
public record AuthorVexStatementRequest(
        String cveId,
        UUID productId,
        String purl,
        VexStatus status,
        VexJustification justification,
        String impactStatement,
        String actionStatement) {
}
