package net.jdesive.secy.service.github;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.service.ProductService;
import net.jdesive.secy.service.SBOMService;
import net.jdesive.secy.service.sbom.SbomParser;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;

/**
 * The GitHub half of Phase 6b's connector sync: enumerate a {@link SourceConnector}'s repos and
 * pull each one's dependency-graph SBOM through the exact same normalized-component/identity/
 * correlation path a manual SPDX upload takes — see {@code SBOMService#ingestDocument}.
 *
 * <h2>Not wrapped in one transaction</h2>
 *
 * <p>Unlike {@code ComplianceService#ingestScanJob} (all-DB, one document already in hand — a single
 * {@code @Transactional} method is fine), this method makes one or more HTTP round-trips per repo.
 * Holding a database transaction open across that would tie up a pooled connection for as long as
 * GitHub takes to answer — the same reason {@code JobRunner#execute} itself holds no transaction and
 * {@code NVDService#ingestData} isn't {@code @Transactional} either, only its per-page
 * {@code saveVulnerabilities} is. Each repo's persistence goes through {@code SBOMService}'s own
 * short {@code @Transactional} methods instead, called one repo at a time.
 *
 * <h2>One bad repo does not fail the sync — and "nothing to sync" is not a failure either</h2>
 *
 * <p>A 404 (dependency graph not enabled, or nothing discoverable), a 403 (rate limit or a
 * scope-restricted token) or any other per-repo failure (a malformed SPDX document, a transient
 * network blip) on one repo is logged and counted, not thrown. This method only throws — so the
 * connector's status can go {@code FAILED}, mirroring {@code Asset}'s "a failed scan degrades to
 * stale, not empty" philosophy that {@code ConnectorSyncService} implements around this call — when
 * there is real evidence something is broken: at least one 403 or genuine error among the targets.
 * <b>An every-repo-404 outcome is deliberately NOT a failure.</b> A 404 is GitHub's own answer for
 * "no dependency graph data here" — a repo with no manifest GitHub recognises, or (very commonly
 * for a personal account) Dependency graph simply never turned on, since private repos do not get
 * it by default. Treating that the same as a broken token/network would fail a connector every
 * time purely because of what the target repos happen to contain, which is not the connector's
 * fault and not something retrying fixes.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GitHubSyncService {

    private final GitHubApiClient gitHubApiClient;
    private final SbomParser sbomParser;
    private final SBOMService sbomService;
    private final ProductService productService;

    public IngestResult sync(SourceConnector connector, JobProgress progress) {
        List<GitHubApiClient.GitHubRepo> repos = gitHubApiClient.listRepos(connector.getScope());

        Set<String> allowlist = connector.getRepoAllowlist();
        List<GitHubApiClient.GitHubRepo> targeted = (allowlist == null || allowlist.isEmpty())
                ? repos
                : repos.stream().filter(repo -> allowlist.contains(repo.fullName())).toList();

        int succeeded = 0;
        int notFound = 0;
        int forbidden = 0;
        int errored = 0;
        int componentsTotal = 0;
        int processed = 0;

        for (GitHubApiClient.GitHubRepo repo : targeted) {
            if (progress.isCancelled()) {
                throw new CancellationException(
                        "Connector sync cancelled after " + processed + " of " + targeted.size() + " repos");
            }

            String fullName = repo.fullName();
            String[] ownerAndRepo = splitOwnerRepo(fullName, connector.getScope(), repo.name());

            try {
                JsonNode sbomNode = gitHubApiClient.fetchDependencyGraphSbom(ownerAndRepo[0], ownerAndRepo[1]);
                if (sbomNode == null || sbomNode.isNull()) {
                    log.info("{}: dependency-graph response carried no SBOM document; skipping", fullName);
                    notFound++;
                } else {
                    NormalizedSbom document = sbomParser.parse(sbomNode);
                    Product product = productService.findOrCreateByName(fullName);
                    SBOM sbom = sbomService.createPlaceholder(
                            product, document, defaultVersion(repo), null, null);
                    IngestResult result = sbomService.ingestDocument(sbom, document, progress);
                    componentsTotal += result.itemsProcessed();
                    succeeded++;
                }
            } catch (HttpClientErrorException.NotFound e) {
                log.info("{}: dependency graph not enabled (404); skipping", fullName);
                notFound++;
            } catch (HttpClientErrorException.Forbidden e) {
                log.warn("{}: 403 fetching dependency graph (rate limit or scope-restricted token); skipping", fullName);
                forbidden++;
            } catch (RuntimeException e) {
                // A malformed SPDX document, a transient network error, anything else -- one bad repo
                // must never take the whole connector sync down with it.
                log.error("{}: failed to sync; skipping and continuing with the rest", fullName, e);
                errored++;
            }

            processed++;
            progress.report(processed, "Synced " + processed + "/" + targeted.size() + " repos ("
                    + succeeded + " ok, " + notFound + " no dependency graph, " + forbidden + " forbidden, "
                    + errored + " errored)");
        }

        String message = String.format(
                "GitHub connector sync: %d/%d repos ingested (%d no dependency graph, %d forbidden, %d errored), %d components",
                succeeded, targeted.size(), notFound, forbidden, errored, componentsTotal);
        log.info(message);

        // FAILED means "something is broken" (a bad/scope-restricted token, a genuine error) — not
        // "GitHub legitimately has nothing to give us". A 404 is GitHub's own answer for "no
        // dependency graph data for this repo", which is a completely ordinary outcome: the repo
        // has no manifest GitHub recognises, or (commonly, for a personal account) Dependency graph
        // was never turned on for it — private repos in particular do NOT get it enabled by default.
        // Every-repo-404 is therefore a clean, if uneventful, sync: a real "0 of N had data"
        // COMPLETED, not a scary stack trace. `forbidden`/`errored` are the actual "something is
        // wrong" signals (a missing/invalid SECY_GITHUB_TOKEN, an out-of-scope token, a transient
        // failure) and still fail the connector.
        if (!targeted.isEmpty() && succeeded == 0 && (forbidden > 0 || errored > 0)) {
            // ConnectorSyncService's catch turns this into SourceConnector.STATUS_FAILED. An empty
            // target list (nothing matched the allowlist, or the org has no repos) never reaches
            // here either — there was nothing to fail at, so it falls through to COMPLETED below.
            throw new IllegalStateException("Every repo failed to sync: " + message);
        }

        String resultMessage = (succeeded == 0 && notFound > 0)
                ? message + " — no repo had GitHub Dependency Graph data available. Check that a repo "
                  + "has a manifest GitHub recognises, and that Dependency graph is turned on under "
                  + "Settings → Security → Code security and analysis (private repos require "
                  + "this explicitly; it is not on by default)."
                : message;
        return new IngestResult(succeeded, resultMessage);
    }

    /** GitHub's {@code full_name} is always {@code owner/repo}; fall back defensively if it is ever missing. */
    private static String[] splitOwnerRepo(String fullName, String scope, String repoName) {
        if (fullName != null) {
            int slash = fullName.indexOf('/');
            if (slash > 0 && slash < fullName.length() - 1) {
                return new String[] {fullName.substring(0, slash), fullName.substring(slash + 1)};
            }
        }
        return new String[] {scope, repoName};
    }

    /** {@code sbom.productVersion} for a connector-synced repo: its default branch, or "Unknown" absent that. */
    private static String defaultVersion(GitHubApiClient.GitHubRepo repo) {
        return repo.defaultBranch() == null || repo.defaultBranch().isBlank() ? "Unknown" : repo.defaultBranch();
    }

}
