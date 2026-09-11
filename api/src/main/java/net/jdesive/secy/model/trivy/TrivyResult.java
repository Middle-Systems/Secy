package net.jdesive.secy.model.trivy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * One scanned target inside a Trivy report.
 *
 * @param target          e.g. {@code alpine:3.18 (alpine 3.18.4)} or {@code app/package-lock.json}
 * @param resultClass     {@code os-pkgs} or {@code lang-pkgs} — JSON field {@code Class}, renamed
 *                        because {@code class} is a Java keyword. This is the field that decides
 *                        whether a package can carry a PURL at all.
 * @param type            the ecosystem within the class: {@code alpine} / {@code debian} / … for
 *                        {@code os-pkgs}, {@code npm} / {@code pip} / {@code gobinary} / … for
 *                        {@code lang-pkgs}
 * @param vulnerabilities the findings; absent (not empty) when the target is clean
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TrivyResult(
        @JsonProperty("Target") String target,
        @JsonProperty("Class") String resultClass,
        @JsonProperty("Type") String type,
        @JsonProperty("Vulnerabilities") List<TrivyVulnerability> vulnerabilities) {

    /** Trivy's own spelling for a target whose packages come from the OS package database. */
    public static final String CLASS_OS_PKGS = "os-pkgs";

    public TrivyResult {
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
    }

    /** True when this target's packages come from the OS package database and have no PURL type. */
    public boolean isOsPackages() {
        return CLASS_OS_PKGS.equalsIgnoreCase(resultClass);
    }

}
