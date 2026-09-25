package net.jdesive.secy.lineage;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Every Cypher relationship type the lineage graph writes, with the {@link NodeLabel} pairs it may
 * legally connect (ROADMAP.md, M1d).
 *
 * <p>Relationship names describe today's data only — see the M1d plan's table of what each roadmap
 * edge maps to and what is deliberately deferred (Repo/Build nodes, Build→Image/Image→Workload
 * edges, Finding/ActionItem, Owner nodes, dependency edges). A future milestone adds a new value
 * plus allowed pairs; it never repurposes one of these.
 */
public enum EdgeType {

    /** {@code Product -[:HAS_SBOM]-> SBOM} */
    HAS_SBOM(pair(NodeLabel.PRODUCT, NodeLabel.SBOM)),

    /** {@code Product -[:HAS_ASSET]-> Asset} */
    HAS_ASSET(pair(NodeLabel.PRODUCT, NodeLabel.ASSET)),

    /** {@code SBOM -[:CONTAINS]-> Component} or {@code Asset -[:CONTAINS]-> AssetComponent} */
    CONTAINS(pair(NodeLabel.SBOM, NodeLabel.COMPONENT), pair(NodeLabel.ASSET, NodeLabel.ASSET_COMPONENT)),

    /**
     * {@code Component -[:HAS_ALERT]-> VulnerabilityAlert} or
     * {@code AssetComponent -[:HAS_ALERT]-> VulnerabilityAlert}
     */
    HAS_ALERT(pair(NodeLabel.COMPONENT, NodeLabel.VULNERABILITY_ALERT),
            pair(NodeLabel.ASSET_COMPONENT, NodeLabel.VULNERABILITY_ALERT)),

    /** {@code VulnerabilityAlert -[:ALERT_FOR]-> Vulnerability} */
    ALERT_FOR(pair(NodeLabel.VULNERABILITY_ALERT, NodeLabel.VULNERABILITY)),

    /**
     * {@code Component -[:HAS_COMPROMISE_FINDING]-> CompromiseFinding} or
     * {@code AssetComponent -[:HAS_COMPROMISE_FINDING]-> CompromiseFinding}
     */
    HAS_COMPROMISE_FINDING(pair(NodeLabel.COMPONENT, NodeLabel.COMPROMISE_FINDING),
            pair(NodeLabel.ASSET_COMPONENT, NodeLabel.COMPROMISE_FINDING));

    /** Every edge carries exactly this one property. */
    public static final List<String> PROPERTY_KEYS = List.of("tenant_id");

    private final List<Map.Entry<NodeLabel, NodeLabel>> allowedPairs;

    // NB: enum constants initialize before any static field in this class body, so the pattern
    // below must be local to the constructor, not a static field referenced from it.
    @SafeVarargs
    EdgeType(Map.Entry<NodeLabel, NodeLabel>... allowedPairs) {
        if (!Pattern.compile("^[A-Z][A-Z_]*$").matcher(name()).matches()) {
            // Enum names ARE the label text for EdgeType, so validate the name itself.
            throw new IllegalStateException("Invalid Cypher relationship type: " + name());
        }
        this.allowedPairs = List.of(allowedPairs);
    }

    /** The Cypher relationship type — always {@code ^[A-Z][A-Z_]*$}. Same as {@link #name()}. */
    public String label() {
        return name();
    }

    /** Every {@code (from, to)} {@link NodeLabel} pair this edge type may legally connect. */
    public List<Map.Entry<NodeLabel, NodeLabel>> allowedPairs() {
        return allowedPairs;
    }

    public boolean allows(NodeLabel from, NodeLabel to) {
        for (Map.Entry<NodeLabel, NodeLabel> pair : allowedPairs) {
            if (pair.getKey() == from && pair.getValue() == to) {
                return true;
            }
        }
        return false;
    }

    private static Map.Entry<NodeLabel, NodeLabel> pair(NodeLabel from, NodeLabel to) {
        return Map.entry(from, to);
    }

}
