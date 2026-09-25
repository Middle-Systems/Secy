package net.jdesive.secy.lineage;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Binds {@link LineageProperties}, mirroring every other feed's {@code *Config} class. */
@Configuration
@EnableConfigurationProperties(LineageProperties.class)
public class LineageConfig {
}
