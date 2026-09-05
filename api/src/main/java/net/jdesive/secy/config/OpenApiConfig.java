package net.jdesive.secy.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * springdoc-openapi wiring. Serves the generated spec at {@code /v3/api-docs} and the
 * browsable UI at {@code /swagger-ui.html} (paths pinned in application.properties).
 */
@Configuration
public class OpenApiConfig {

    private static final String FALLBACK_VERSION = "0.0.1-SNAPSHOT";

    /**
     * @param buildProperties present when the build emitted {@code META-INF/build-info.properties}
     *                        (see the {@code springBoot { buildInfo() }} block in build.gradle);
     *                        absent when running straight from an IDE compile, hence the fallback.
     */
    @Bean
    public OpenAPI secyOpenAPI(ObjectProvider<BuildProperties> buildProperties) {
        String version = buildProperties.getIfAvailable() != null
                ? buildProperties.getIfAvailable().getVersion()
                : FALLBACK_VERSION;

        return new OpenAPI().info(new Info()
                .title("Secy API")
                .description("""
                        Security posture management for the Secy platform. Ingests vulnerability \
                        intelligence (NVD, FIRST EPSS, CISA KEV) and CIS/docker compliance reports, \
                        correlates it against assets described by CycloneDX SBOMs, and surfaces the \
                        actionable subset — anything KEV-listed or with an EPSS score above 0.1.""")
                .version(version)
                .license(new License()
                        .name("AGPL-3.0")
                        .url("https://www.gnu.org/licenses/agpl-3.0.html")));
    }
}
