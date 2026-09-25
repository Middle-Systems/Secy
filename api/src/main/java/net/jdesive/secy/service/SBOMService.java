package net.jdesive.secy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.events.SbomUploadedEvent;
import net.jdesive.secy.model.component.ComponentIdentityAssessor;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.*;
import net.jdesive.secy.service.sbom.ComponentIdentityService;
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
 * <p>Phase 6b added a third entry point, {@link #ingestDocument}, which is what {@link #ingestUploadJob}
 * itself now delegates to after its find-by-job-id/re-parse step: the normalized-model → storage
 * persistence work alone, for a caller ({@code GitHubSyncService}) that already holds a loaded
 * {@code SBOM} row and a parsed {@link NormalizedSbom} and has no job-id indirection to unwind.
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
@Slf4j
@Service
public class SBOMService {

    private final SBOMRepository sbomRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;
    private final SbomParser sbomParser;
    private final ComponentIdentityService componentIdentityService;

    /** {@code sbom_component.description}. SPDX descriptions routinely run past this. */
    private static final int MAX_DESCRIPTION = 1024;

    /** {@code sbom_component.purl} / {@code sbom_license.license} / {@code sbom_reference.url}. */
    private static final int MAX_PURL = 512;
    private static final int MAX_SHORT_TEXT = 255;

    @Autowired
    public SBOMService(SBOMRepository sbomRepository, ApplicationEventPublisher eventPublisher,
                       ObjectMapper objectMapper, SbomParser sbomParser,
                       ComponentIdentityService componentIdentityService) {
        this.sbomRepository = sbomRepository;
        this.eventPublisher = eventPublisher;
        this.objectMapper = objectMapper;
        this.sbomParser = sbomParser;
        this.componentIdentityService = componentIdentityService;
    }

    /**
     * Persist a placeholder row for an upload that is about to be queued: enough for the
     * controller's {@code 202} response to carry a real id, and to hold what {@link #ingestUploadJob}
     * will need to finish the work. No components are attached yet, and {@code status} is
     * {@code QUEUED} — matching the job's own starting state.
     *
     * <p>{@code rawBody} and {@code jobId} may both be null — {@code GitHubSyncService} does this for
     * each repo it syncs: it already has the parsed {@link NormalizedSbom} in hand within its own
     * {@code CONNECTOR_SYNC} job, so there is nothing to stash for a later job-id lookup, and it calls
     * {@link #ingestDocument} directly rather than {@link #ingestUploadJob}.
     */
    @Transactional
    public SBOM createPlaceholder(Product product, NormalizedSbom document, String productVersion,
                                  String rawBody, UUID jobId) {
        return createPlaceholder(product, document, productVersion, rawBody, jobId, null, null);
    }

    /**
     * The same placeholder creation, additionally recording M1c provenance: which channel the upload
     * came through and, for a connector sync, which {@link SourceConnector}. The 5-arg overload above
     * delegates here with both null. Delegates to the 8-arg overload with a null {@code explicitStage}
     * — the document's own declared stage (if any) still applies; see that overload.
     */
    @Transactional
    public SBOM createPlaceholder(Product product, NormalizedSbom document, String productVersion,
                                  String rawBody, UUID jobId, SbomIngestionSource ingestionSource,
                                  UUID sourceConnectorId) {
        return createPlaceholder(product, document, productVersion, rawBody, jobId, ingestionSource,
                sourceConnectorId, null);
    }

    /**
     * The same placeholder creation, additionally resolving and recording the M1e lifecycle stage.
     *
     * <h2>Stage resolution</h2>
     *
     * <p>{@code explicitStage} — the {@code ?stage=} API param, or {@link SbomLifecycleStage#SOURCE}
     * for a GitHub connector sync — wins when given. Otherwise the document's own declared stage
     * (CycloneDX {@code metadata.lifecycles[]}; always null for SPDX) is used. If both are given and
     * disagree, the explicit one wins and the disagreement is logged — an operator naming
     * {@code ?stage=build} on a document that itself declares {@code pre-build} almost certainly knows
     * something the document's metadata does not.
     *
     * <h2>The active-SBOM slot (M1e)</h2>
     *
     * <p>The active slot key is {@code (product, lifecycleStage)}, not {@code product} alone — see
     * {@link #deactivateSupersededSboms}. Skipped entirely for the Unassigned bucket (M1a): its SBOMs
     * are unrelated documents that happened to arrive untagged, not versions of one another or of each
     * other's stage, so there is no "old version" to deactivate — every bucket SBOM stays active,
     * whatever stage it records. See {@code Product}'s class Javadoc and
     * {@code CorrelationService}/{@code CompromiseDetectionService}, which correlate a bucket SBOM at
     * its own scope rather than the whole-product scope this deactivation exists to serve.
     */
    @Transactional
    public SBOM createPlaceholder(Product product, NormalizedSbom document, String productVersion,
                                  String rawBody, UUID jobId, SbomIngestionSource ingestionSource,
                                  UUID sourceConnectorId, SbomLifecycleStage explicitStage) {
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
        sbom.setIngestionSource(ingestionSource);
        sbom.setSourceConnectorId(sourceConnectorId);

        SbomLifecycleStage documentStage = document.declaredLifecycleStage();
        SbomLifecycleStage resolved = explicitStage != null ? explicitStage : documentStage;
        if (explicitStage != null && documentStage != null && explicitStage != documentStage) {
            log.warn("SBOM upload declares lifecycle stage {} in its document metadata but the "
                    + "request specified {} — the explicit stage wins", documentStage, explicitStage);
        }
        sbom.setLifecycleStage(resolved);

        // The new upload becomes the active SBOM immediately, matching the old synchronous
        // behaviour — the upload is "the current one" from the moment it is accepted, even while its
        // components are still being persisted.
        if (!product.isUnassigned()) {
            deactivateSupersededSboms(product, resolved);
        }
        sbom.setActive(true);

        return sbomRepository.saveAndFlush(sbom);
    }

    /**
     * The persistence half of an upload, run inside the {@code SBOM_UPLOAD} job rather than on the
     * request thread. Looks the placeholder row up by the job that owns it, re-parses the raw body
     * {@code SBOMController} stashed on it, and hands off to {@link #ingestDocument} for the actual
     * component persistence.
     *
     * @throws IllegalStateException if the job's SBOM row is missing or its raw body is already
     *                               consumed/absent
     */
    @Transactional
    public IngestResult ingestUploadJob(UUID jobId, JobProgress progress) {
        SBOM sbom = sbomRepository.findByJobId(jobId)
                .orElseThrow(() -> new IllegalStateException("No SBOM row is waiting on upload job " + jobId));

        NormalizedSbom document = reparse(sbom.getPendingRawBody());
        return ingestDocument(sbom, document, progress);
    }

    /**
     * The normalized-model → storage persistence step itself, factored out of {@link #ingestUploadJob}
     * (Phase 6b) so a caller that already holds a loaded {@link SBOM} row and a freshly-parsed
     * {@link NormalizedSbom} — rather than a job id and a stashed raw body to re-parse — can drive the
     * exact same component/identity/correlation path a manual upload takes.
     *
     * <p>{@code GitHubSyncService} is that caller: a {@code CONNECTOR_SYNC} job processes many repos,
     * not one document behind one job id, so the {@code find-by-jobId-then-reparse} indirection
     * {@link #ingestUploadJob} needs — which exists only because {@code SBOMController} must hand back
     * a real id before the document is actually processed — does not apply. The connector sync builds
     * its own placeholder row per repo (see {@link #createPlaceholder}, called with a null job id/raw
     * body since nothing is pending on it) and a document it has already fetched and parsed
     * synchronously within the job, then calls this directly, once per repo.
     *
     * <p>Sets {@code sbom.status} to {@code PROCESSING} itself (both callers start from a row whose
     * status is not yet that), persists the components/tools, clears any stashed raw body, and
     * publishes {@link SbomUploadedEvent} exactly as before — so {@code VulnerabilityScanner}'s async
     * scan (and the {@code PROCESSING -> COMPLETED/FAILED} transition it performs) fires for both
     * callers identically.
     */
    @Transactional
    public IngestResult ingestDocument(SBOM sbom, NormalizedSbom document, JobProgress progress) {
        sbom.setStatus("PROCESSING");
        sbomRepository.saveAndFlush(sbom);

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

        // M1c Pass B: the cross-instance hash-identity-collision sweep, tenant-wide. Runs inside this
        // same transaction (REQUIRED propagation) and after the save/flush above so every component
        // on this SBOM has an id and a computed identityKey to compare against the rest of the tenant.
        componentIdentityService.flagHashIdentityCollisions(saved);

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

    /**
     * The M1e active-SBOM slot rule. The active slot key is {@code (product, lifecycleStage)}, not
     * {@code product} alone: a normal product holds either exactly one active stage-less SBOM (legacy
     * mode, the pre-M1e behaviour), or at most one active SBOM per stage with no stage-less one
     * (staged mode) — the two modes never mix.
     *
     * <ul>
     *   <li><b>{@code stage} is non-null (a staged upload):</b> deactivate every active SBOM of the
     *       product whose stage is {@code stage} OR null. A stage-less SBOM was the pre-M1e "whole
     *       product" truth; adopting stages supersedes it.</li>
     *   <li><b>{@code stage} is null (an unstaged upload):</b> deactivate EVERY active SBOM of the
     *       product, staged or not — exactly the pre-M1e meaning, "this is the product's whole truth
     *       now".</li>
     * </ul>
     *
     * <p>Called before the new row is saved, so {@code findAllByProductIdAndActiveTrue} never sees it
     * — every row this touches is an existing, already-persisted one, and it dirty-flushes through the
     * normal managed-entity mechanism, same as the pre-M1e code.
     *
     * <p>Deliberately no DB-level uniqueness constraint enforces this — the Unassigned bucket
     * legitimately holds many active SBOMs and a partial index cannot see {@code products.unassigned}
     * — so a race between two concurrent same-stage uploads is possible, exactly as a race on the old
     * whole-product slot was. Read paths use {@code findFirst...OrderByUploadDateDesc} to tolerate it.
     */
    private void deactivateSupersededSboms(Product product, SbomLifecycleStage stage) {
        for (SBOM old : sbomRepository.findAllByProductIdAndActiveTrue(product.getId())) {
            if (stage == null || old.getLifecycleStage() == null || old.getLifecycleStage() == stage) {
                old.setActive(false);
            }
        }
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

        // M1c: declared CPE/SWID identifiers, persisted verbatim (the normalizer already dropped
        // over-long values — never truncate identifierValue here, same reasoning as the hash loop
        // above). declaredName/declaredVersion are already length-bounded by SecondaryIdentifiers.
        for (NormalizedComponent.Identifier identifier : component.identifiers()) {
            SBOMComponentIdentifier row = new SBOMComponentIdentifier();
            row.setIdentifierType(identifier.type());
            row.setIdentifierValue(identifier.value());
            row.setDeclaredName(identifier.declaredName());
            row.setDeclaredVersion(identifier.declaredVersion());
            row.setSource(identifier.source());
            row.setComponent(entity);
            entity.getIdentifiers().add(row);
        }

        // M1c Pass A: does this instance's own declared identifiers corroborate or conflict with its
        // primary identity? CVE-independent, computed once here rather than at correlation time — see
        // ComponentIdentityAssessor's Javadoc and IdentityConfidence's orthogonality note versus
        // MatchConfidence. Deliberately not in @PrePersist/@PreUpdate: Pass B (flagHashIdentityCollisions)
        // runs after this and must be able to set CONFLICTING on an already-assessed row without a
        // lifecycle callback clobbering it back on the next flush.
        ComponentIdentityAssessor.IdentityAssessment assessment = ComponentIdentityAssessor.assess(component);
        entity.setIdentityConfidence(assessment.confidence());
        for (ComponentIdentityAssessor.DetectedConflict conflict : assessment.conflicts()) {
            SBOMComponentIdentityConflict row = new SBOMComponentIdentityConflict();
            row.setConflictType(conflict.type());
            row.setIdentifierType(conflict.identifierType());
            row.setIdentifierValue(conflict.identifierValue());
            row.setDetail(conflict.detail());
            row.setOtherComponentId(null);
            row.setOtherIdentityKey(null);
            row.setDetectedAt(LocalDateTime.now());
            row.setComponent(entity);
            entity.getIdentityConflicts().add(row);
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
