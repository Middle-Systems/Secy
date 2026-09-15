package net.jdesive.secy.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds the supply-chain compromise knobs. Its own {@code @Configuration}, mirroring
 * {@link ActionableConfig} and {@link OsvConfig}, so the two Phase 6 feeds and the IOC aging
 * threshold can evolve independently of the funnel's EPSS threshold.
 */
@Configuration
@EnableConfigurationProperties(CompromiseProperties.class)
public class CompromiseConfig {
}
