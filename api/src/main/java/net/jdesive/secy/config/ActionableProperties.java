package net.jdesive.secy.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code secy.actionable.*} — see the "Actionable funnel" block in {@code application.properties}.
 *
 * <p>The default is repeated here because the test profile replaces
 * {@code application.properties} outright rather than merging with it.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.actionable")
public class ActionableProperties {

    /**
     * An alert is promoted to actionable when its CVE's EPSS probability is <b>strictly</b> above
     * this value (or the CVE is KEV-listed). {@code SECY_ACTIONABLE_EPSS_THRESHOLD}.
     */
    private double epssThreshold = 0.1;

}
