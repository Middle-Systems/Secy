package net.jdesive.secy.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code secy.osv.*} — see the "OSV mirror" block in {@code application.properties}.
 *
 * <p>The default ecosystem list is repeated here (as the Java field initialiser) because the test
 * profile replaces {@code application.properties} outright rather than merging with it, and because
 * Spring only overwrites a {@code @ConfigurationProperties} field when it finds a matching key —
 * leaving this default in place for any profile that doesn't set {@code secy.osv.ecosystems}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.osv")
public class OsvProperties {

    /**
     * OSV ecosystem names to mirror, exactly as they appear in the export path
     * ({@code https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip}).
     * {@code SECY_OSV_ECOSYSTEMS}, comma-separated.
     */
    private List<String> ecosystems = new ArrayList<>(List.of(
            "npm", "Maven", "PyPI", "Go", "NuGet", "RubyGems", "crates.io", "Packagist", "Hex", "Pub"));

}
