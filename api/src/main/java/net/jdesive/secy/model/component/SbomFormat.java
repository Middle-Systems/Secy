package net.jdesive.secy.model.component;

/**
 * The SBOM document formats Secy ingests.
 *
 * <p>{@link #label()} is what lands in {@code sbom.format} and what the UI renders, so it is the
 * format's own spelling rather than the enum constant.
 */
public enum SbomFormat {

    CYCLONEDX("CycloneDX"),
    SPDX("SPDX");

    private final String label;

    SbomFormat(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

}
