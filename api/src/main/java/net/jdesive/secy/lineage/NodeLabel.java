package net.jdesive.secy.lineage;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Every Cypher vertex label the lineage graph writes, in write order (ROADMAP.md, M1d).
 *
 * <p>Declaration order is the order {@link net.jdesive.secy.lineage.CypherRenderer} emits {@code
 * CREATE} statements in and the primary sort key for a snapshot's node list — see {@link
 * net.jdesive.secy.lineage.model.LineageGraphSnapshot}. Adding a label for a future milestone
 * (M1j/M2/M3) is additive: append a value, add its {@link #propertyKeys()}, and add one new
 * planner method — no retrofit of the values already here.
 *
 * <p>Every label starts with {@code tenant_id, pg_id} — see each value's Javadoc for the rest of
 * its property schema, and {@code ROADMAP.md}'s M1d plan for why each property was chosen (and why
 * others — descriptions, raw bodies, anything secret-shaped — were deliberately excluded).
 */
public enum NodeLabel {

    /** A catalog {@code Product} row, including the per-tenant Unassigned bucket (M1a). */
    PRODUCT("Product", "name", "tag_value", "unassigned", "created_at"),

    /** An active {@code SBOM} row. Labeled {@code SBOM}, not {@code Build} — see the M1d plan. */
    SBOM("SBOM", "format", "spec_version", "version", "product_version", "status", "upload_date",
            "ingestion_source", "source_connector_id", "lifecycle_stage"),

    /** A non-root {@code sbom_component} row belonging to an included {@link #SBOM}. */
    COMPONENT("Component", "name", "version", "purl", "identity_key", "component_type", "identity_confidence"),

    /** An {@code Asset} row. */
    ASSET("Asset", "asset_type", "name", "status", "scanner", "last_scanned_at"),

    /** A present-in-last-scan {@code asset_component} row belonging to an included {@link #ASSET}. */
    ASSET_COMPONENT("AssetComponent", "name", "version", "purl", "identity_key", "ecosystem", "source"),

    /** A CVE record, materialized once per tenant per CVE id (never shared across tenants). */
    VULNERABILITY("Vulnerability", "base_severity", "cvss_score", "cve_status"),

    /** One {@code (component, CVE)} match — its own node so M1j's ActionItem has something to attach to. */
    VULNERABILITY_ALERT("VulnerabilityAlert", "cve_id", "lifecycle_state", "triage_state", "actionable",
            "actionable_reason", "match_confidence", "fix_state", "exploit_maturity", "cvss_score",
            "epss_score", "kev_due_date"),

    /** A {@code CompromiseFinding} row. */
    COMPROMISE_FINDING("CompromiseFinding", "compromise_type", "confidence", "severity", "source",
            "ioc_id", "lifecycle_state", "triage_state");

    // NB: enum constants initialize before any static field in this class body, regardless of
    // textual order -- so the pattern and prefix below must be local to the constructor, not
    // static fields referenced from it.
    private final String label;

    private final List<String> propertyKeys;

    NodeLabel(String label, String... ownPropertyKeys) {
        if (!Pattern.compile("^[A-Z][A-Za-z]*$").matcher(label).matches()) {
            throw new IllegalArgumentException("Invalid Cypher vertex label: " + label);
        }
        List<String> keys = new java.util.ArrayList<>(List.of("tenant_id", "pg_id"));
        keys.addAll(List.of(ownPropertyKeys));
        this.label = label;
        this.propertyKeys = List.copyOf(keys);
    }

    /** The Cypher label — always {@code ^[A-Z][A-Za-z]*$}. */
    public String label() {
        return label;
    }

    /** This label's full, fixed property schema, always starting {@code tenant_id, pg_id}. */
    public List<String> propertyKeys() {
        return propertyKeys;
    }

}
