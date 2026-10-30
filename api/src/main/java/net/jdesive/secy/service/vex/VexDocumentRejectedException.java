package net.jdesive.secy.service.vex;

/**
 * A VEX document is unparseable, or not one of the three supported shapes (OpenVEX / CSAF 2.0 VEX
 * subset / CycloneDX VEX). Mapped to {@code 400} by {@code VexController} — thrown synchronously
 * before anything is queued.
 */
public class VexDocumentRejectedException extends RuntimeException {

    public VexDocumentRejectedException(String message) {
        super(message);
    }

}
