package net.jdesive.secy.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds the actionable-funnel knobs. Kept as its own {@code @Configuration} rather than folded into
 * {@link AsyncConfig} so the funnel and the ingestion queue can evolve independently.
 */
@Configuration
@EnableConfigurationProperties(ActionableProperties.class)
public class ActionableConfig {
}
