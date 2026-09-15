package net.jdesive.secy.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code secy.compromise.*} — see the "Supply-chain compromise detection" block in
 * {@code application.properties}.
 *
 * <p>Every default is repeated here as a Java field initialiser, because the test profile replaces
 * {@code application.properties} outright rather than merging with it and Spring only overwrites a
 * {@code @ConfigurationProperties} field when it finds a matching key. Same reason
 * {@link OsvProperties} and {@link ActionableProperties} do it.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secy.compromise")
public class CompromiseProperties {

    /* ------------------------------------------------------------------ */
    /* Feed: OpenSSF Malicious Packages                                   */
    /* ------------------------------------------------------------------ */

    /**
     * Zip of the {@code ossf/malicious-packages} repository.
     *
     * <p><b>Why a repository archive and not a GCS export.</b> OSSF publishes no bulk export of its
     * own; the records reach OSV.dev's per-ecosystem {@code all.zip} instead, where they are mixed in
     * with ordinary advisories — the npm export is 215 MB and 97% of it is {@code MAL-} records. Secy
     * already mirrors those exports for Phase 2 and already has to download them; pulling them a
     * second time for a different table would double a very large transfer to extract the same
     * records. GitHub's {@code codeload} archive is the authoritative source, is directory-scoped by
     * ecosystem so {@link #ecosystems} can be honoured without parsing, and needs no credentials.
     *
     * <p>{@code SECY_COMPROMISE_MALICIOUS_PACKAGES_URL}.
     */
    private String maliciousPackagesUrl =
            "https://codeload.github.com/ossf/malicious-packages/zip/refs/heads/main";

    /**
     * Which of the archive's {@code osv/malicious/<ecosystem>/} directories to ingest, by their
     * <em>upstream directory name</em> (lower-case: {@code npm}, {@code pypi}, {@code maven}, …), not
     * by the OSV ecosystem spelling. The ecosystem actually stored comes from each record's own
     * {@code affected[].package.ecosystem}, so these two never have to agree.
     *
     * <p>An empty list means "every directory". {@code SECY_COMPROMISE_ECOSYSTEMS}, comma-separated.
     */
    private List<String> ecosystems = new ArrayList<>(List.of(
            "npm", "pypi", "maven", "go", "nuget", "packagist", "rubygems", "crates.io"));

    /* ------------------------------------------------------------------ */
    /* Feed: abuse.ch MalwareBazaar                                       */
    /* ------------------------------------------------------------------ */

    /**
     * MalwareBazaar's public CSV export.
     *
     * <p><b>The API-key situation, stated plainly.</b> abuse.ch's JSON API
     * ({@code https://mb-api.abuse.ch/api/v1/}) requires an {@code Auth-Key} header and answers
     * {@code {"error": "Unauthorized"}} without one. The CSV exports —
     * {@code /export/csv/recent/} (the last few hundred samples, ~380 KB) and
     * {@code /export/csv/full/} (the whole corpus, ~220 MB zipped) — are, as of this writing, served
     * without any credential. Secy defaults to the keyless CSV so the feed works out of the box, and
     * sends {@link #malwareBazaarApiKey} as an {@code Auth-Key} header whenever one is configured, so
     * an operator who has a key is covered if abuse.ch gates the exports too.
     *
     * <p>Point this at {@code https://bazaar.abuse.ch/export/csv/full/} for the complete corpus; the
     * ingester detects a zip payload by its magic bytes and unpacks it, so the same knob takes
     * either. {@code SECY_MALWAREBAZAAR_EXPORT_URL}.
     */
    private String malwareBazaarUrl = "https://bazaar.abuse.ch/export/csv/recent/";

    /**
     * Optional abuse.ch {@code Auth-Key}, free from {@code https://auth.abuse.ch/}.
     *
     * <p>Blank by default and <b>not required</b> — unlike {@code NVD_API_KEY}, whose absence only
     * costs rate limit, this one costs nothing at all while the CSV export stays open. It is sent as
     * an {@code Auth-Key} header when set. If abuse.ch ever closes the export, the ingest fails with
     * the transport's own 401 and the job row carries that message; there is no silent degradation.
     * {@code SECY_MALWAREBAZAAR_API_KEY}.
     */
    private String malwareBazaarApiKey = "";

    /* ------------------------------------------------------------------ */
    /* IOC aging                                                          */
    /* ------------------------------------------------------------------ */

    /**
     * How long an IOC may go un-re-observed by its feed before a {@code CONFIRMED}/{@code LIKELY}
     * finding is demoted to {@code INVESTIGATE}.
     *
     * <p>90 days is a deliberate compromise. Short enough that a malicious package the registry
     * pulled two years ago stops shouting {@code CRITICAL} at an operator forever; long enough that a
     * quarterly ingest cadence does not age out a corpus that has not actually changed. Measured
     * against {@code CompromiseFinding.freshnessReference()}.
     *
     * <p>{@code SECY_COMPROMISE_IOC_STALE_AFTER}, ISO-8601 duration ({@code P90D}, {@code P30D}).
     */
    private Duration iocStaleAfter = Duration.ofDays(90);

    /**
     * Whether the nightly aging sweep runs. Independent of {@code secy.jobs.scheduler-enabled}, which
     * governs the ingestion queue's own two timers. {@code SECY_COMPROMISE_AGING_ENABLED}.
     */
    private boolean agingEnabled = true;

}
