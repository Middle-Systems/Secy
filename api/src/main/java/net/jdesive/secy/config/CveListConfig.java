package net.jdesive.secy.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds the CVE List v5 / Vulnrichment feed's knobs. Kept as its own {@code @Configuration},
 * mirroring {@link OsvConfig}, so the feed's config can evolve independently.
 */
@Configuration
@EnableConfigurationProperties(CveListProperties.class)
public class CveListConfig {
}
