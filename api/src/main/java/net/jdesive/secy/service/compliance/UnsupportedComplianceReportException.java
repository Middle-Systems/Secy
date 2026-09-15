package net.jdesive.secy.service.compliance;

/** The uploaded document is not a Trivy compliance report. Surfaces as a plain {@code 400}. */
public class UnsupportedComplianceReportException extends RuntimeException {

    public UnsupportedComplianceReportException(String message) {
        super(message);
    }

    public UnsupportedComplianceReportException(String message, Throwable cause) {
        super(message, cause);
    }

}
