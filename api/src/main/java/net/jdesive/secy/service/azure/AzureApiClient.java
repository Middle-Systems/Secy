package net.jdesive.secy.service.azure;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

/**
 * The Azure Resource Manager / Microsoft Defender for Cloud REST calls {@code AzureSyncService}
 * needs, authenticated with a single instance-wide service principal — the same
 * {@code @Value}-read-env-var pattern {@code GitHubApiClient.token} uses, not a per-connector
 * credential (see {@code SourceConnectorType}'s class Javadoc for why).
 *
 * <h2>No Azure SDK</h2>
 *
 * <p>Azure Resource Manager and Defender for Cloud are plain OAuth2-bearer-token REST APIs, unlike
 * AWS's SigV4-signed calls — a client-credentials token fetch followed by ordinary bearer-token
 * {@code GET}/{@code POST}s through the shared {@code RestTemplate} bean is all that is needed, the
 * same shape every other integration in this codebase (NVD/KEV/EPSS/OSV/CVE-List/GitHub) already
 * uses. No {@code azure-identity} or {@code com.azure:*} dependency was added.
 *
 * <h2>Not verified against a live tenant</h2>
 *
 * <p>Unlike {@code GitHubApiClient}, this sandbox has no Azure credentials to exercise these
 * endpoints against, so the shapes below are coded from Microsoft's documented, stable ARM API
 * contracts rather than confirmed live. Every response is read defensively through Jackson
 * {@link JsonNode} rather than a rigid POJO tree so a minor field-name surprise cannot crash the
 * parse — see {@code AzureSyncService} for how sparse/differently-shaped Defender data is handled.
 */
@Slf4j
@Service
public class AzureApiClient {

    private static final String ARM_BASE = "https://management.azure.com";

    private final RestTemplate restTemplate;

    @Value("${secy.azure.tenant-id:}")
    private String tenantId;

    @Value("${secy.azure.client-id:}")
    private String clientId;

    @Value("${secy.azure.client-secret:}")
    private String clientSecret;

    public AzureApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /** One ARM resource as either the VM or ACR registry listing reports it. */
    public record AzureResource(String id, String name, String loginServer) {
    }

    /**
     * A client-credentials token good for {@code management.azure.com}, fetched fresh for this sync
     * run — no cross-run caching, matching the roadmap's "fetch once per sync" instruction.
     *
     * @throws org.springframework.web.client.HttpClientErrorException.Unauthorized bad client
     *         secret/id
     * @throws org.springframework.web.client.HttpClientErrorException.Forbidden   tenant/app
     *         disallowed
     */
    public String fetchAccessToken() {
        String url = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", "https://management.azure.com/.default");

        ResponseEntity<JsonNode> response =
                restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(form, headers), JsonNode.class);
        JsonNode body = response.getBody();
        String token = body == null ? null : textOrNull(body, "access_token");
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("Azure token endpoint responded without an access_token");
        }
        return token;
    }

    /** Every VM in the subscription, following {@code nextLink} until there isn't one. */
    public List<AzureResource> listVirtualMachines(String subscriptionId, String accessToken) {
        String firstUrl = ARM_BASE + "/subscriptions/" + subscriptionId
                + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01";
        return paginateResources(firstUrl, accessToken, node -> new AzureResource(
                textOrNull(node, "id"), textOrNull(node, "name"), null));
    }

    /** Every ACR registry in the subscription, following {@code nextLink} until there isn't one. */
    public List<AzureResource> listContainerRegistries(String subscriptionId, String accessToken) {
        String firstUrl = ARM_BASE + "/subscriptions/" + subscriptionId
                + "/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview";
        return paginateResources(firstUrl, accessToken, node -> {
            JsonNode properties = node.get("properties");
            String loginServer = properties == null ? null : textOrNull(properties, "loginServer");
            return new AzureResource(textOrNull(node, "id"), textOrNull(node, "name"), loginServer);
        });
    }

    /**
     * Every Defender for Cloud security assessment in the subscription. An empty list is the
     * ordinary, common outcome when Defender for Cloud (an opt-in paid tier) is not enabled — see
     * {@code AzureSyncService} for why that is not treated as a failure.
     */
    public List<JsonNode> listSecurityAssessments(String subscriptionId, String accessToken) {
        String firstUrl = ARM_BASE + "/subscriptions/" + subscriptionId
                + "/providers/Microsoft.Security/assessments?api-version=2020-01-01";
        return paginateNodes(firstUrl, accessToken);
    }

    /**
     * The vulnerability-level detail behind one assessment. {@code assessmentId} is already a full
     * ARM resource id (as {@link #listSecurityAssessments} returns it), so it is appended to
     * {@code management.azure.com} directly rather than re-built from parts.
     */
    public List<JsonNode> listSubAssessments(String assessmentId, String accessToken) {
        String firstUrl = ARM_BASE + assessmentId + "/subAssessments?api-version=2019-01-01-preview";
        return paginateNodes(firstUrl, accessToken);
    }

    /* ------------------------------------------------------------------ */
    /* Pagination                                                         */
    /* ------------------------------------------------------------------ */

    private List<AzureResource> paginateResources(
            String firstUrl, String accessToken, java.util.function.Function<JsonNode, AzureResource> mapper) {
        List<AzureResource> resources = new ArrayList<>();
        String url = firstUrl;
        while (url != null) {
            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(url, HttpMethod.GET, authenticatedEntity(accessToken), JsonNode.class);
            JsonNode body = response.getBody();
            JsonNode value = body == null ? null : body.get("value");
            if (value != null && value.isArray()) {
                for (JsonNode node : value) {
                    resources.add(mapper.apply(node));
                }
            }
            url = body == null ? null : textOrNull(body, "nextLink");
        }
        return resources;
    }

    private List<JsonNode> paginateNodes(String firstUrl, String accessToken) {
        List<JsonNode> nodes = new ArrayList<>();
        String url = firstUrl;
        while (url != null) {
            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(url, HttpMethod.GET, authenticatedEntity(accessToken), JsonNode.class);
            JsonNode body = response.getBody();
            JsonNode value = body == null ? null : body.get("value");
            if (value != null && value.isArray()) {
                value.forEach(nodes::add);
            }
            url = body == null ? null : textOrNull(body, "nextLink");
        }
        return nodes;
    }

    private static HttpEntity<?> authenticatedEntity(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return new HttpEntity<>(headers);
    }

    static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

}
