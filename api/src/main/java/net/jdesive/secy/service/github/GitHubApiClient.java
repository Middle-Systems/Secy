package net.jdesive.secy.service.github;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * The two GitHub REST calls {@code GitHubSyncService} needs — repo listing and each repo's
 * dependency-graph SBOM — authenticated with a single instance-wide token, the same
 * {@code @Value}-read-env-var pattern {@code NVDService.apiKey} uses (see that class), not a
 * per-connector credential (see {@code SourceConnector}'s class Javadoc for why).
 *
 * <h2>Verified against the live API</h2>
 *
 * <p>This sandbox had outbound internet access, so both endpoints below were exercised directly
 * against {@code api.github.com} (unauthenticated, against public repos/orgs) while writing this
 * class, rather than coded from documentation alone:
 *
 * <ul>
 *   <li>{@code GET /repos/{owner}/{repo}/dependency-graph/sbom} really does nest the SPDX document
 *       under a top-level {@code "sbom"} key — confirmed against
 *       {@code octocat/Hello-World}.</li>
 *   <li>Pagination really is {@code Link} response header, RFC 5988 style —
 *       {@code <url>; rel="next", <url>; rel="last"} — confirmed against {@code GET /orgs/github/repos}.</li>
 *   <li>{@code GET /orgs/{login}/repos} really does 404 (not e.g. redirect or 422) when
 *       {@code login} is a user account rather than an organization — confirmed against
 *       {@code GET /orgs/octocat/repos}, which is what {@link #listRepos} falls back on.</li>
 *   <li>A nonexistent repo's dependency-graph endpoint 404s with the standard
 *       {@code {"message": "Not Found", ...}} body — confirmed, and it doesn't matter what the body
 *       says since the caller only looks at the status code.</li>
 * </ul>
 *
 * <p>Not verified from here (no token to test with, and the roadmap says not to spend long chasing
 * sandbox network limits): a 403 from a scope-restricted token or from hitting the unauthenticated
 * rate limit while polling. Both are handled by status code alone — the body is never parsed for
 * either — so this is a documentation gap, not an untested code path.
 */
@Slf4j
@Service
public class GitHubApiClient {

    private static final String API_HOST = "api.github.com";
    private static final String API_BASE = "https://" + API_HOST;
    private static final int PER_PAGE = 100;

    private final RestTemplate restTemplate;

    @Value("${secy.github.token:}")
    private String token;

    public GitHubApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /** One repo as {@code GET /orgs|users/{scope}/repos} reports it. */
    public record GitHubRepo(String name, String fullName, String defaultBranch) {
    }

    /**
     * List every repo the token can see under {@code scope}, paginating via the {@code Link} header
     * until there is no {@code rel="next"} left.
     *
     * <p>Tries the organization endpoint first and falls back to the user endpoint on a 404 — GitHub
     * has no single "repos for this login, whatever kind of account it is" endpoint, and
     * distinguishing org-vs-user ahead of time would need a third call ({@code GET /users/{login}})
     * for no real benefit. v1 keeps this to the two-call fallback the roadmap suggests rather than
     * pre-detecting the account type.
     */
    public List<GitHubRepo> listRepos(String scope) {
        try {
            return paginate(API_BASE + "/orgs/" + scope + "/repos?per_page=" + PER_PAGE);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("'{}' is not an organization login (404 from /orgs); falling back to /users", scope);
            return paginate(API_BASE + "/users/" + scope + "/repos?per_page=" + PER_PAGE);
        }
    }

    private List<GitHubRepo> paginate(String firstUrl) {
        List<GitHubRepo> repos = new ArrayList<>();
        String url = firstUrl;
        while (url != null) {
            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(url, HttpMethod.GET, authenticatedEntity(), JsonNode.class);
            JsonNode body = response.getBody();
            if (body != null && body.isArray()) {
                for (JsonNode repo : body) {
                    repos.add(new GitHubRepo(
                            textOrNull(repo, "name"),
                            textOrNull(repo, "full_name"),
                            textOrNull(repo, "default_branch")));
                }
            }
            url = nextPageUrl(response.getHeaders());
        }
        return repos;
    }

    /**
     * The dependency-graph SBOM for one repo — the SPDX document nested under the response's
     * {@code "sbom"} key (see the class Javadoc), unwrapped here so every other caller only ever
     * deals in SPDX documents.
     *
     * @throws HttpClientErrorException.NotFound   dependency graph not enabled for this repo, or the
     *                                              repo has nothing discoverable — the caller (
     *                                              {@code GitHubSyncService}) treats this as a skip,
     *                                              not a failure
     * @throws HttpClientErrorException.Forbidden  rate limit or a scope-restricted token — also a
     *                                              per-repo skip, not a failure, in the caller
     */
    public JsonNode fetchDependencyGraphSbom(String owner, String repo) {
        String url = API_BASE + "/repos/" + owner + "/" + repo + "/dependency-graph/sbom";
        ResponseEntity<JsonNode> response =
                restTemplate.exchange(url, HttpMethod.GET, authenticatedEntity(), JsonNode.class);
        JsonNode body = response.getBody();
        return body == null ? null : body.get("sbom");
    }

    private HttpEntity<?> authenticatedEntity() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, "application/vnd.github+json");
        if (token != null && !token.isBlank()) {
            headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return new HttpEntity<>(headers);
    }

    /** {@code rel="next"} out of an RFC 5988 {@code Link} header, or null once there isn't one. */
    private static String nextPageUrl(HttpHeaders headers) {
        List<String> linkHeaders = headers.get(HttpHeaders.LINK);
        if (linkHeaders == null) {
            return null;
        }
        for (String header : linkHeaders) {
            for (String part : header.split(",")) {
                String trimmed = part.trim();
                if (trimmed.contains("rel=\"next\"")) {
                    int start = trimmed.indexOf('<');
                    int end = trimmed.indexOf('>');
                    if (start >= 0 && end > start) {
                        return sameOriginOrNull(trimmed.substring(start + 1, end));
                    }
                }
            }
        }
        return null;
    }

    /**
     * The {@code Link} header is response data, and every request carries the instance-wide token, so
     * a next-page URL is only followed when it points back at {@code https://api.github.com} — and is
     * then rebuilt on the fixed base rather than used verbatim, so nothing in the header can steer the
     * token to another host. Anything else ends pagination with a warning.
     */
    private static String sameOriginOrNull(String link) {
        try {
            URI uri = new URI(link);
            boolean sameOrigin = "https".equalsIgnoreCase(uri.getScheme())
                    && API_HOST.equalsIgnoreCase(uri.getHost())
                    && uri.getRawUserInfo() == null
                    && (uri.getPort() == -1 || uri.getPort() == 443)
                    && uri.getRawPath() != null
                    && uri.getRawPath().startsWith("/");
            if (sameOrigin) {
                String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
                return "https://api.github.com/" + uri.getRawPath().substring(1) + query;
            }
        } catch (URISyntaxException e) {
            // fall through
        }
        log.warn("Ignoring next-page link that does not point at {}: {}", API_BASE, link);
        return null;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

}
