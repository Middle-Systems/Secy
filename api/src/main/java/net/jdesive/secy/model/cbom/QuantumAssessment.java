package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus;

/**
 * The M1g quantum-vulnerability verdict for one crypto asset, produced by
 * {@code QuantumVulnerabilityClassifier}.
 *
 * @param status    Shor-vulnerable, not, or undetermined
 * @param family    which broken family, when {@code status == VULNERABLE}; null otherwise
 * @param basis     what evidence decided it
 * @param indicator the matched OID/name token/curve/ref/cipher-suite name that decided it (≤255)
 * @param primitive the deciding algorithm's own primitive — its own, or a referenced asset's when
 *                  that is what decided the verdict — used for the migration-hint text
 */
public record QuantumAssessment(QuantumVulnerabilityStatus status, QuantumVulnerableFamily family,
                                QuantumClassificationBasis basis, String indicator, String primitive) {

    public static final QuantumAssessment UNKNOWN =
            new QuantumAssessment(QuantumVulnerabilityStatus.UNKNOWN, null, null, null, null);

}
