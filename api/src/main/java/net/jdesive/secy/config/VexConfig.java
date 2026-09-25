package net.jdesive.secy.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds the VEX upload/parsing knobs. Its own {@code @Configuration}, mirroring
 * {@link ActionableConfig}, so the VEX subsystem can evolve independently.
 */
@Configuration
@EnableConfigurationProperties(VexProperties.class)
public class VexConfig {
}
