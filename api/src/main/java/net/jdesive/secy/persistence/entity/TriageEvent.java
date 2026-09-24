package net.jdesive.secy.persistence.entity;

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

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One append-only row of triage history: a state transition, a free-text comment, or both at once
 * (a comment attached to the same call that moved the state).
 *
 * <p>Two nullable FKs with an XOR invariant, the same pattern {@link VulnerabilityAlert#component}/
 * {@link VulnerabilityAlert#assetComponent} established — {@link #vulnerabilityAlert} for an event
 * against a CVE-backed alert, {@link #compromiseFinding} for one against a compromise finding.
 * Enforced here by the self-clearing setters and in the database by the
 * {@code ck_triage_event_one_parent} check constraint from migration {@code 014}, and never by JPA
 * inheritance over a shared "triageable" parent — this codebase does not have one, on purpose (see
 * {@code CompromiseFinding}'s class Javadoc for why a shared table/hierarchy was rejected for the
 * funnel itself).
 *
 * <p>{@link #fromState}/{@link #toState} are both null for a pure comment with no state change, and
 * both set for a transition. {@link #comment} may accompany either, or stand alone.
 */
@Getter
@Setter
@Entity
@Table(name = "triage_event",
        indexes = {
                @Index(name = "idx_triage_event_vuln_alert", columnList = "vulnerability_alert_id"),
                @Index(name = "idx_triage_event_compromise_finding", columnList = "compromise_finding_id")
        })
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class TriageEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The alert this event is about, when it is about a {@link VulnerabilityAlert}. Mutually exclusive with {@link #compromiseFinding}. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vulnerability_alert_id")
    @ToString.Exclude
    private VulnerabilityAlert vulnerabilityAlert;

    /** The finding this event is about, when it is about a {@link CompromiseFinding}. Mutually exclusive with {@link #vulnerabilityAlert}. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "compromise_finding_id")
    @ToString.Exclude
    private CompromiseFinding compromiseFinding;

    /** Sets the alert and clears the finding: exactly one may be set. */
    public void setVulnerabilityAlert(VulnerabilityAlert vulnerabilityAlert) {
        this.vulnerabilityAlert = vulnerabilityAlert;
        if (vulnerabilityAlert != null) {
            this.compromiseFinding = null;
        }
    }

    /** Sets the finding and clears the alert: exactly one may be set. */
    public void setCompromiseFinding(CompromiseFinding compromiseFinding) {
        this.compromiseFinding = compromiseFinding;
        if (compromiseFinding != null) {
            this.vulnerabilityAlert = null;
        }
    }

    /** The state before this event. Null for a pure comment. */
    @Enumerated(EnumType.STRING)
    @Column(name = "from_state", length = 16)
    private TriageState fromState;

    /** The state after this event. Null for a pure comment. */
    @Enumerated(EnumType.STRING)
    @Column(name = "to_state", length = 16)
    private TriageState toState;

    /** Free-text note, optionally accompanying a state change. */
    @Column(length = 4096)
    private String comment;

    /** Who made this change. Every event is attributed — never null. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "changed_by_id", nullable = false)
    @ToString.Exclude
    private User changedBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

}
