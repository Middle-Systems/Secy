package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.events.SbomUploadedEvent;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.*;
import net.jdesive.secy.service.sbom.SbomParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Persists an SBOM upload and kicks off its scan.
 *
 * <h2>Two phases, two transactions</h2>
 *
 * <p>Phase 3 moved the parse-into-components-and-persist step off the request thread and onto the
 * {@code SBOM_UPLOAD} job queue (see {@code JobRunner}, {@code SbomIngestJobService}), so this class
 * now has two entry points instead of one:
 *
 * <ul>
 *   <li>{@link #createPlaceholder} — runs synchronously in {@code SBOMController}, after
 *       {@code SbomParser} has already validated the document (a 400 for a bad shape happens before
 *       this is ever called). Writes a bare {@code sbom} row — no components yet — carrying the raw
 *       JSON body and the id of the job that will finish the job. That gives the {@code 202}
 *       response a real id to report immediately.</li>
 *   <li>{@link #ingestUploadJob} — runs inside the {@code SBOM_UPLOAD} job, on a worker thread. Reads
 *       the placeholder back by the job's id, re-parses the stashed body (parsing is a pure, cheap
 *       function of the bytes — re-running it here is simpler and safer than trying to serialize
 *       {@link NormalizedSbom}'s record tree through a column of its own), and does the actual
 *       component persistence that {@code ingestAndPrepare} used to do inline.</li>
 * </ul>
 *
 * <p>Format detection/parsing itself lives in {@code SbomParser} and is identical for both phases —
 * everything downstream of it, in both phases, is identical for CycloneDX and SPDX uploads.
 *
 * <h2>Component rows are per-SBOM; component <em>identity</em> is per-product</h2>
 *
 * <p>Each upload still writes its own {@code sbom_component} rows. That is deliberate, not
 * leftover: an SBOM version is a snapshot of what the product shipped at that moment, and sharing
 * rows across versions would erase the very membership a history diff needs to read. What carries
 * across versions is {@link SBOMComponent#getIdentityKey()} — the version-less PURL — which is the
 * key {@code CorrelationService} upserts alerts on. So the same dependency in v1 and v2 has two rows
 * and one identity, and its alerts follow the identity.
 */
@Service
public class SBOMService {

    private final SBOMRepository sbomRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;
    private final SbomParser sbomParser;

    /** {@code sbom_component.description}. SPDX descriptions routinely run past this. */
    private static final int MAX_DESCRIPTION = 1024;

    /** {@code sbom_component.purl} / {@code sbom_license.license} / {@code sbom_reference.url}. */
    private static final int MAX_PURL = 512;
    private static final int MAX_SHORT_TEXT = 255;

    @Autowired
    public SBOMService(SBOMRepository sbomRepository, ApplicationEventPublisher eventPublisher,
                       ObjectMapper objectMapper, SbomParser sbomParser) {
        this.sbomRepository = sbomRepository;
        this.eventPublisher = eventPublisher;
        this.objectMapper = objectMapper;
        this.sbomParser = sbomParser;
    }

    /**
     * Persist a placeholder row for an upload that is about to be queued: enough for the
     * controller's {@code 202} response to carry a real id, and to hold what {@link #ingestUploadJob}
     * will need to finish the work. No components are attached yet, and {@code status} is
     * {@code QUEUED} — matching the job's own starting state.
     */
    @Transactional
    public SBOM createPlaceholder(Product product, NormalizedSbom document, String productVersion,
                                  String rawBody, UUID jobId) {
        SBOM sbom = new SBOM();
        sbom.setFormat(document.format().label());
        sbom.setSpecVersion(truncate(document.specVersion(), MAX_SHORT_TEXT));
        sbom.setVersion(document.version());
        sbom.setProductVersion(productVersion);
        sbom.setProduct(product);
        sbom.setStatus("QUEUED");
        sbom.setUploadDate(LocalDateTime.now());
        sbom.setPendingRawBody(rawBody);
        sbom.setJobId(jobId);

        // Versioning logic: the new upload becomes the active SBOM immediately, matching the old
        // synchronous behaviour — the upload is "the current one" from the moment it is accepted,
        // even while its components are still being persisted.
        deactivateOldSboms(product);
        sbom.setActive(true);

        return sbomRepository.saveAndFlush(sbom);
    }

    /**
     * The persistence half of an upload, run inside the {@code SBOM_UPLOAD} job rather than on the
     * request thread. Looks the placeholder row up by the job that owns it, re-parses the raw body
     * {@code SBOMController} stashed on it, and creates the real component/tool rows. On success this
     * publishes the same {@link SbomUploadedEvent} the old synchronous path did, so
     * {@code VulnerabilityScanner}'s async scan (and the {@code PROCESSING -> COMPLETED/FAILED}
     * transition it performs) is unaffected.
     *
     * @throws IllegalStateException if the job's SBOM row is missing or its raw body is already
     *                               consumed/absent
     */
    @Transactional
    public IngestResult ingestUploadJob(UUID jobId, JobProgress progress) {
        SBOM sbom = sbomRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No SBOM row is waiting on upload job " + jobId));

        sbom.setStatus("PROCESSING");
        sbomRepository.saveAndFlush(sbom);

        NormalizedSbom document = reparse(sbom.getPendingRawBody());

        if (document.rootComponent() != null) {
            sbom.setComponent(toEntity(document.rootComponent(), sbom));
        }
        for (NormalizedComponent component : document.components()) {
            sbom.getComponents().add(toEntity(component, sbom));
        }
        for (NormalizedSbom.NormalizedTool tool : document.tools()) {
            SBOMTool sbomTool = new SBOMTool();
            sbomTool.setName(truncate(tool.name(), MAX_SHORT_TEXT));
            sbomTool.setVersion(truncate(tool.version(), MAX_SHORT_TEXT));
            sbomTool.setGroup(truncate(tool.group(), MAX_SHORT_TEXT));
            sbomTool.setType(truncate(tool.type(), MAX_SHORT_TEXT));
            sbomTool.setSbom(sbom);
            sbom.getTools().add(sbomTool);
        }

        // Consumed — no reason to keep a (possibly large) copy of the raw upload around.
        sbom.setPendingRawBody(null);
        SBOM saved = sbomRepository.saveAndFlush(sbom);

        int componentCount = document.components().size();
        progress.report(componentCount, "Persisted " + componentCount + " components; vulnerability scan starting");

        // Trigger Async Scan — same event, same listener, as the old synchronous path.
        eventPublisher.publishEvent(new SbomUploadedEvent(saved.getId()));

        return IngestResult.of(componentCount, document.format().label() + " SBOM components ingested");
    }

    /**
     * Move the SBOM row for a failed upload job to {@code FAILED} so the UI does not show a
     * permanently-stuck "processing" state.
     *
     * <p>Runs in its own transaction: the failure came from {@link #ingestUploadJob} throwing, which
     * already rolled its transaction — and everything written inside it, including the
     * {@code PROCESSING} status — back. A fresh {@code REQUIRES_NEW} transaction is what lets this
     * write actually stick.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markUploadJobFailed(UUID jobId) {
        sbomRepository.findByJobId(jobId).ifPresent(sbom -> {
            sbom.setStatus("FAILED");
            sbom.setPendingRawBody(null);
            sbomRepository.save(sbom);
        });
    }

    private NormalizedSbom reparse(String rawBody) {
        if (rawBody == null || rawBody.isBlank()) {
            throw new IllegalStateException(
                    "SBOM row has no pending raw body to ingest — it was already processed, or never received one.");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(rawBody);
        } catch (IOException e) {
            // SBOMController already validated this exact document once; this only fires if the
            // stashed text were corrupted at rest, which the original 400 path never sees.
            throw new IllegalStateException("Stashed SBOM body failed to re-parse as JSON: " + e.getMessage(), e);
        }
        return sbomParser.parse(root);
    }

    private void deactivateOldSboms(Product product) {
        // Find current active SBOM for this product and set active = false
        sbomRepository.findByProductIdAndActiveTrue(product.getId())
                .ifPresent(old -> old.setActive(false));
    }

    /**
     * The single normalized-model → storage-model mapping. Both parsers land here (via
     * {@link #ingestUploadJob}) and nothing else writes an {@code SBOMComponent} on the upload path.
     *
     * <p>{@code identityKey} is not set here — {@link SBOMComponent#refreshIdentityKey()} derives it
     * on persist, so it is right for every writer, not just this one.
     */
    private SBOMComponent toEntity(NormalizedComponent component, SBOM sbom) {
        SBOMComponent entity = new SBOMComponent();
        entity.setName(truncate(component.name(), MAX_SHORT_TEXT));
        entity.setDescription(truncate(component.description(), MAX_DESCRIPTION));
        entity.setVersion(truncate(component.version(), MAX_SHORT_TEXT));
        entity.setType(truncate(component.type(), MAX_SHORT_TEXT));
        entity.setBomRef(truncate(component.bomRef(), MAX_SHORT_TEXT));
        entity.setPurl(truncate(component.purl(), MAX_PURL));
        entity.setSbom(sbom);

        for (String license : component.licenses()) {
            SBOMLicense sbomLicense = new SBOMLicense();
            sbomLicense.setLicense(truncate(license, MAX_SHORT_TEXT));
            sbomLicense.setComponent(entity);
            entity.getLicenses().add(sbomLicense);
        }

        for (NormalizedComponent.ExternalReference reference : component.externalReferences()) {
            SBOMReference sbomReference = new SBOMReference();
            sbomReference.setType(truncate(reference.type(), MAX_SHORT_TEXT));
            sbomReference.setUrl(truncate(reference.url(), MAX_SHORT_TEXT));
            sbomReference.setComponent(entity);
            entity.getReferences().add(sbomReference);
        }

        // Digests the document declared (CycloneDX hashes[] / SPDX checksums[]). Already normalised
        // and validated by the parsers via ComponentHash.of, so nothing here can be malformed — and
        // deliberately NOT truncated: a clipped digest is not a shorter digest, it is a wrong one
        // that would silently never match. Over-long values were dropped at parse time instead.
        for (NormalizedComponent.ComponentHashValue hash : component.hashes()) {
            ComponentHash normalized = ComponentHash.of(hash.algorithm(), hash.value());
            if (normalized != null) {
                entity.getHashes().add(normalized);
            }
        }

        return entity;
    }

    /**
     * Ingest hardening: an over-long field truncates rather than failing the whole upload. A
     * description clipped at 1024 characters costs nothing; a rejected SBOM costs the user every
     * component in it.
     */
    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    public SBOM getSbomById(UUID sbomId) {
        Optional<SBOM> sbomOptional = this.sbomRepository.findById(sbomId);
        if (!sbomOptional.isPresent()) {
            throw new RuntimeException("Error finding sbom with id " + sbomId);
        }
        return sbomOptional.get();
    }
}
