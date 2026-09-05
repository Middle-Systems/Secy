package net.jdesive.secy.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
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

    /** Referenced by name from {@code @SecurityRequirement} annotations on the controllers. */
    private static final String BEARER_SCHEME = "bearerAuth";

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

        return new OpenAPI()
                // Declared once and applied to every operation, which is what puts the "Authorize"
                // button in Swagger UI. Endpoints that are genuinely anonymous (/auth/login,
                // /auth/register) simply ignore the header they are sent.
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Paste the `token` from POST /auth/login.")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME))
                .info(new Info()
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
