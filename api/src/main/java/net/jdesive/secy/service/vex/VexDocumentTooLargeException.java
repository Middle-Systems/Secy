package net.jdesive.secy.service.vex;

/** A VEX upload exceeded {@code secy.vex.max-document-bytes}. Mapped to {@code 413} by {@code VexController}. */
public class VexDocumentTooLargeException extends RuntimeException {

    public VexDocumentTooLargeException(String message) {
        super(message);
    }

}
