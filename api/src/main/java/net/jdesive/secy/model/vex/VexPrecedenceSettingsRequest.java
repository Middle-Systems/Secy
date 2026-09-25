package net.jdesive.secy.model.vex;

/** {@code PUT /vex/settings/precedence} body. {@code policy} is validated case-insensitively. */
public record VexPrecedenceSettingsRequest(String policy) {
}
