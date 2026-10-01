package net.jdesive.secy.service.vex;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.model.vex.AuthorVexStatementRequest;
import net.jdesive.secy.model.vex.ParsedVexDocument;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.VexDocument;
import net.jdesive.secy.persistence.entity.VexOrigin;
import net.jdesive.secy.service.vex.parser.VexParsing;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Authors a TENANT-origin OpenVEX {@code not_affected} (or other status) statement on a user's
 * behalf and runs it through M1f's EXISTING ingestion pipeline unchanged (M1k — ROADMAP.md's
 * "Role-based views" §7/§9). This is what makes both {@code POST /vex/statements} (security-engineer
 * VEX authoring) and the software-engineer "dispute" flow ({@code ActionItemDisputeService}) work: a
 * dispute IS one of these, nothing more.
 *
 * <p>Validates synchronously, before anything is queued — same contract as {@code POST /vex}
 * (see {@code VexController}): {@link InvalidVexUploadException} for a 400, a 404
 * {@code ResponseStatusException} for an unknown product, and otherwise the same
 * parse-then-queue-a-{@code VEX_UPLOAD}-job path {@code VexController.upload} runs, so a newer
 * statement from the same (lower-cased email) author on the same target supersedes an older one
 * under the EXISTING author-supersession rule, and an opposing TENANT statement from someone else
 * triggers M1f's EXISTING conflict flagging — no new state, no new review mechanism.
 */
@Service
@RequiredArgsConstructor
public class VexAuthoringService {

    private static final int MAX_TEXT_LENGTH = 4096;

    private final VexDocumentParser vexDocumentParser;
    private final VexIngestionService vexIngestionService;
    private final ProductRepository productRepository;
    private final JobService jobService;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public AuthoredVex author(AuthorVexStatementRequest req, String authorEmail, Principal principal) {
        if (req == null) {
            throw new InvalidVexUploadException("request body is required");
        }

        List<String> cveIds = VexParsing.cveIds(req.cveId());
        if (cveIds.isEmpty()) {
            throw new InvalidVexUploadException("cveId '" + req.cveId() + "' is not a recognisable CVE id");
        }
        String cveId = cveIds.get(0);

        if (req.status() == null) {
            throw new InvalidVexUploadException("status is required");
        }
        boolean hasJustification = req.justification() != null;
        boolean hasImpactStatement = req.impactStatement() != null && !req.impactStatement().isBlank();
        if (req.status() == net.jdesive.secy.persistence.entity.VexStatus.NOT_AFFECTED
                && !hasJustification && !hasImpactStatement) {
            throw new InvalidVexUploadException(
                    "NOT_AFFECTED requires a justification or a non-blank impactStatement");
        }

        VexParsing.PurlTarget purlTarget = VexParsing.purlTarget(req.purl());
        if (purlTarget.matchKey() == null) {
            throw new InvalidVexUploadException("purl '" + req.purl() + "' did not resolve to a matchable component");
        }

        requireWithinLength("impactStatement", req.impactStatement());
        requireWithinLength("actionStatement", req.actionStatement());

        if (req.productId() != null) {
            Product product = productRepository.findById(req.productId()).orElse(null);
            if (product == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Product not found: " + req.productId());
            }
            if (product.isUnassigned()) {
                throw new InvalidVexUploadException("VEX cannot be scoped to the Unassigned bucket");
            }
        }

        byte[] body = buildOpenVexDocument(cveId, req, authorEmail);
        ParsedVexDocument parsed = vexDocumentParser.parse(body);

        Job job = jobService.create(JobType.VEX_UPLOAD, principal);
        VexDocument placeholder = vexIngestionService.createPlaceholder(
                parsed, body, VexOrigin.TENANT, req.productId(), job.getId());

        return new AuthoredVex(job, placeholder.getId());
    }

    private static void requireWithinLength(String field, String value) {
        if (value != null && value.length() > MAX_TEXT_LENGTH) {
            throw new InvalidVexUploadException(field + " is " + value.length() + " characters, over the "
                    + MAX_TEXT_LENGTH + " limit");
        }
    }

    private byte[] buildOpenVexDocument(String cveId, AuthorVexStatementRequest req, String authorEmail) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("@context", "https://openvex.dev/ns/v0.2.0");
        root.put("@id", "urn:secy:vex:authored:" + UUID.randomUUID());
        root.put("author", authorEmail == null ? "unknown" : authorEmail);
        root.put("timestamp", OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        root.put("version", 1);

        ArrayNode statements = root.putArray("statements");
        ObjectNode statement = statements.addObject();
        statement.putObject("vulnerability").put("name", cveId);
        statement.putArray("products").addObject().put("@id", req.purl());
        statement.put("status", req.status().name().toLowerCase(Locale.ROOT));
        if (req.justification() != null) {
            statement.put("justification", req.justification().name().toLowerCase(Locale.ROOT));
        }
        if (req.impactStatement() != null && !req.impactStatement().isBlank()) {
            statement.put("impact_statement", req.impactStatement());
        }
        if (req.actionStatement() != null && !req.actionStatement().isBlank()) {
            statement.put("action_statement", req.actionStatement());
        }
        try {
            return objectMapper.writeValueAsBytes(root);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize an authored OpenVEX document", e);
        }
    }

}
