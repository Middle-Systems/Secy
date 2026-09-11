package net.jdesive.secy.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code secy.cve-list.*} — see the "CVE List v5 / Vulnrichment" block in
 * {@code application.properties}.
 *
 * <p>The default mirrors {@code OsvProperties}: repeated here as the Java field initialiser because
 * the test profile replaces {@code application.properties} outright rather than merging with it, and
 * because Spring only overwrites a {@code @ConfigurationProperties} field when it finds a matching
 * key — leaving this default in place for any profile that doesn't set
 * {@code secy.cve-list.releases-api-url}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.cve-list")
public class CveListProperties {

    /**
     * GitHub releases API URL used to discover the current bulk-snapshot zip asset, rather than
     * hardcoding its (periodically renamed) filename. {@code SECY_CVE_LIST_RELEASES_API_URL}.
     * Pointed at a stub server in tests.
     */
    private String releasesApiUrl = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";

}
