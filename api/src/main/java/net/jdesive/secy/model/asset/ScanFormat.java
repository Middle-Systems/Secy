package net.jdesive.secy.model.asset;

/** Which scanner produced a scan document. One endpoint per value, and the body must match. */
public enum ScanFormat {

    /** {@code trivy image -f json} (also {@code trivy fs}/{@code trivy repo} — same report shape). */
    TRIVY("Trivy"),

    /** {@code grype <target> -o json}. */
    GRYPE("Grype");

    private final String label;

    ScanFormat(String label) {
        this.label = label;
    }

    /** Human-readable name, used in log lines, error messages and {@code asset.scanner}. */
    public String label() {
        return label;
    }

}
