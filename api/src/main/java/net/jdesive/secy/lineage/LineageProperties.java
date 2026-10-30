package net.jdesive.secy.lineage;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * {@code secy.lineage.*} — see the "Lineage graph" block in {@code application.properties}.
 *
 * <p>The default is repeated in {@code src/test/resources/application.properties} because that
 * file replaces the main one outright rather than merging with it (same pattern every other
 * {@code @ConfigurationProperties} class in this codebase follows — see {@code IngestionJobProperties}).
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "secy.lineage")
public class LineageProperties {

    /**
     * Master switch. {@code false} by default so pulling this branch never breaks a Postgres
     * without the AGE extension installed — {@link AgeLineageGraphWriter} only exists as a bean
     * when this is {@code true} (see its {@code @ConditionalOnProperty}). {@code SECY_LINEAGE_ENABLED}.
     */
    private boolean enabled = false;

    /**
     * The AGE shared library name passed to {@code LOAD '<name>'} before every write, when
     * non-blank. Validated against a safe filename/path shape — this string is concatenated
     * directly into a {@code LOAD} statement (Postgres extensions have no parameterized-load form),
     * so it must never come from anything but this trusted, operator-set config value.
     * {@code SECY_LINEAGE_AGE_LIBRARY}.
     */
    @Pattern(regexp = "^[A-Za-z0-9_$/.-]*$", message = "must be a safe library name/path")
    private String ageLibrary = "age";

    /** Rows per {@code UNWIND} batch when rendering a rebuild. {@code SECY_LINEAGE_BATCH_SIZE}. */
    private int batchSize = 500;

}
