package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.jdesive.secy.model.component.CorrelatableComponent;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * "You are shipping something known-bad" — one component matched against one malicious-package
 * record or malware sample.
 *
 * <h2>Why this is not a {@code VulnerabilityAlert}</h2>
 *
 * <p>Because it has no CVE, and never can. A {@code VulnerabilityAlert}'s every enrichment column is
 * derived from a {@code Vulnerability} row: EPSS, KEV, exploit maturity, CVSS, the fix version. A
 * malicious package has none of those — there is no score to rank it by, no KEV entry to check, and
 * no fixed release to upgrade to, because the remediation is <em>removal</em>, not a version bump.
 * Forcing it into the alert table would mean a permanently-null second class of row whose
 * {@code vulnerability_id} FK is null, which breaks the one invariant every query in Phases 1-5
 * relies on, and would put the funnel's KEV/EPSS predicate in the position of having to special-case
 * rows it cannot evaluate. That is the {@code DockerVulnerabilityAlert} mistake in reverse.
 *
 * <p>So: its own table, its own promotion path, and a <b>typed union</b> at the API edge. See
 * {@code ActionableService} for how {@code GET /actionable} returns both from one paged list, and
 * {@code PHASE6-CONTRACT.md} §4 for the response shape.
 *
 * <h2>What it does share with a {@code VulnerabilityAlert}</h2>
 *
 * <p>Everything about <em>where</em> the finding is. The component reference is the same
 * two-nullable-FKs-with-an-XOR pattern Phase 4 established — {@link #component} for an SBOM
 * component, {@link #assetComponent} for one a scanner found on an asset — with the same
 * self-clearing setters and the same {@link CorrelatableComponent} accessor. A compromise finding on
 * an image and one in a product's SBOM are the same kind of statement about two different artefacts,
 * exactly as their alerts are.
 *
 * <p>And the same lifecycle: {@link AlertLifecycleState}, reconciled by
 * {@code CompromiseDetectionService} on every re-scan. A finding a re-scan no longer reproduces is
 * {@link AlertLifecycleState#AUTO_RESOLVED}, never deleted — Phase 2's rule, unchanged.
 *
 * <h2>Severity</h2>
 *
 * <p>Fixed at {@link #SEVERITY} ({@code CRITICAL}) for every row, and <b>not configurable</b> in
 * Phase 6. There is deliberately no {@code secy.compromise.severity} knob: unlike the EPSS threshold,
 * which trades noise against coverage on a continuum, "am I shipping malware" has no continuum to
 * tune. The column exists rather than the value being a constant in the mapper so a later phase can
 * vary it per type or per source without a migration; nothing writes anything else today.
 */
@Getter
@Setter
@Entity
@Table(name = "compromise_finding",
        indexes = {
                @Index(name = "idx_compromise_finding_component", columnList = "component_id"),
                @Index(name = "idx_compromise_finding_asset_component", columnList = "asset_component_id"),
                @Index(name = "idx_compromise_finding_state", columnList = "lifecycle_state"),
                @Index(name = "idx_compromise_finding_ioc", columnList = "ioc_id"),
                @Index(name = "idx_compromise_finding_triage_state", columnList = "triage_state")
        })
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class CompromiseFinding {

    /** The one severity a compromise finding ever has. See the class note. */
    public static final String SEVERITY = "CRITICAL";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /* ------------------------------------------------------------------ */
    /* What was found                                                     */
    /* ------------------------------------------------------------------ */

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private CompromiseType type;

    /**
     * How firmly this artefact is implicated. Written by {@code CompromiseDetectionService} from the
     * evidence and then re-checked against IOC staleness by {@code CompromiseAgingService} — both go
     * through the same staleness rule, so the two can never disagree about a decayed IOC.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private CompromiseConfidence confidence = CompromiseConfidence.LIKELY;

    /** Always {@link #SEVERITY}. */
    @Column(nullable = false, length = 16)
    private String severity = SEVERITY;

    /** Human-readable feed name — {@code OpenSSF Malicious Packages} / {@code abuse.ch MalwareBazaar}. */
    @Column(nullable = false, length = 255)
    private String source;

    /**
     * The feed's id for the indicator: a {@code MAL-…} record id, or the SHA-256 itself for a
     * malware-hash finding. Together with {@link #type} and the component identity this is the
     * reconciliation key — see {@code CompromiseDetectionService}.
     */
    @Column(name = "ioc_id", nullable = false, length = 255)
    private String iocId;

    /**
     * The value that actually matched, as the operator would recognise it: the component's PURL
     * (or {@code ecosystem/name@version} when it has none) for a malicious package, the lower-case
     * SHA-256 for a malware hash.
     *
     * <p>Distinct from {@link #iocId} on purpose. {@code iocId} identifies the <em>feed record</em>;
     * this identifies <em>the thing of yours</em> that hit it, which is what the UI shows and what
     * makes a finding explainable without a second lookup.
     */
    @Column(name = "matched_on", nullable = false, length = 512)
    private String matchedOn;

    /** The record's own summary — "Malicious code in bucket-protocol-sdk-v2 (npm)", or the family name. */
    @Column(length = 1024)
    private String summary;

    /** The feed's write-up, when it has one. Rendered in the detail drawer, never queried. */
    @Column(length = 10024)
    private String details;

    /** Comma-joined reporting origins / the submitting reporter. Provenance for the drawer. */
    @Column(length = 512)
    private String origins;

    /** The feed record's {@code references[]} as raw JSON, when it carried any. */
    @Column(name = "references_json", length = 4096)
    private String referencesJson;

    /* ------------------------------------------------------------------ */
    /* The IOC's own freshness                                            */
    /* ------------------------------------------------------------------ */

    /** When the feed first saw this indicator. Copied off the feed row at detection time. */
    @Column(name = "ioc_first_seen")
    private LocalDateTime iocFirstSeen;

    /**
     * When the feed last saw this indicator. <b>This is what IOC aging measures against</b>; see
     * {@code CompromiseAgingService} and {@link MalwareHash#getLastSeen()} for what "last seen" means
     * per feed.
     */
    @Column(name = "ioc_last_seen")
    private LocalDateTime iocLastSeen;

    /** The feed's own 0–1 conviction about the indicator, when it expresses one. */
    @Column(name = "ioc_confidence")
    private Double iocConfidence;

    /**
     * When IOC aging last demoted this finding. Null until it has been aged, which is also how the
     * aging job stays idempotent: a row already at {@link CompromiseConfidence#INVESTIGATE} is not
     * touched again.
     */
    @Column(name = "aged_at")
    private LocalDateTime agedAt;

    /* ------------------------------------------------------------------ */
    /* Where it is — the Phase 4 XOR pair                                 */
    /* ------------------------------------------------------------------ */

    /** The affected component when it came from an SBOM. Mutually exclusive with {@link #assetComponent}. */
    @JsonIgnoreProperties({"vulnerabilityAlerts", "sbom"})
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "component_id")
    @ToString.Exclude
    private SBOMComponent component;

    /** The affected component when a scanner found it on an {@link Asset}. Mutually exclusive with {@link #component}. */
    @JsonIgnoreProperties({"asset"})
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_component_id")
    @ToString.Exclude
    private AssetComponent assetComponent;

    /** Whichever component this finding cites. See {@code CorrelatableComponent}. */
    @JsonIgnore
    public CorrelatableComponent getCorrelatableComponent() {
        return component != null ? component : assetComponent;
    }

    /** Sets the SBOM component and clears the asset one: exactly one may be set. */
    public void setComponent(SBOMComponent component) {
        this.component = component;
        if (component != null) {
            this.assetComponent = null;
        }
    }

    /** Sets the asset component and clears the SBOM one: exactly one may be set. */
    public void setAssetComponent(AssetComponent assetComponent) {
        this.assetComponent = assetComponent;
        if (assetComponent != null) {
            this.component = null;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                          */
    /* ------------------------------------------------------------------ */

    /**
     * Whether the most recent detection pass over the owning scope still reproduced this match.
     * {@code GET /actionable} and the default {@code GET /compromise} return only
     * {@link AlertLifecycleState#ACTIVE} rows.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_state", nullable = false, length = 16)
    private AlertLifecycleState lifecycleState = AlertLifecycleState.ACTIVE;

    /** When detection last confirmed this match. */
    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    /** When the finding was first raised. */
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        if (this.severity == null) {
            this.severity = SEVERITY;
        }
    }

    /**
     * The freshness timestamp IOC aging measures. Falls back through
     * {@code iocLastSeen → iocFirstSeen → createdAt} so a feed row that carried no timestamps at all
     * still ages — from when Secy first learned of it — rather than being exempt forever.
     */
    @JsonIgnore
    public LocalDateTime freshnessReference() {
        if (iocLastSeen != null) {
            return iocLastSeen;
        }
        if (iocFirstSeen != null) {
            return iocFirstSeen;
        }
        return createdAt;
    }

    /* ------------------------------------------------------------------ */
    /* Phase 7 — triage                                                   */
    /* ------------------------------------------------------------------ */

    /**
     * What a person decided about this finding. Orthogonal to {@link #lifecycleState} — see
     * {@link AlertLifecycleState}'s Javadoc for why the two never merge.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "triage_state", nullable = false, length = 16)
    private TriageState triageState = TriageState.OPEN;

    /** When a {@link TriageState#SNOOZED} finding should reappear on the default list. Meaningless otherwise. */
    @Column(name = "snoozed_until")
    private LocalDateTime snoozedUntil;

    /** Who is on this, if anyone. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assignee_id")
    @ToString.Exclude
    private User assignee;

}
