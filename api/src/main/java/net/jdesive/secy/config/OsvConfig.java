package net.jdesive.secy.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds the OSV mirror knobs. Kept as its own {@code @Configuration}, mirroring
 * {@link ActionableConfig}, so the feed's config can evolve independently.
 */
@Configuration
@EnableConfigurationProperties(OsvProperties.class)
public class OsvConfig {
}
