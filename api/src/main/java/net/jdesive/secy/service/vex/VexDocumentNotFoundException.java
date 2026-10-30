package net.jdesive.secy.service.vex;

import java.util.UUID;

/** No {@code VexDocument} with the given id. Mapped to {@code 404} by {@code VexController}. */
public class VexDocumentNotFoundException extends RuntimeException {

    public VexDocumentNotFoundException(UUID id) {
        super("No VEX document with id " + id);
    }

}
