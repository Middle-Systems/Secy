package net.jdesive.secy.service.vex.parser;

import com.fasterxml.jackson.databind.JsonNode;
import net.jdesive.secy.config.VexProperties;
import net.jdesive.secy.model.vex.ParsedVexDocument;

/**
 * The public seam into this package's three format parsers, each of which is package-private on
 * purpose — {@code VexDocumentParser} (in {@code service.vex}) is the only caller, and everything
 * else about a format's own shape stays contained here.
 */
public final class VexFormatParsers {

    private VexFormatParsers() {
    }

    public static ParsedVexDocument openVex(JsonNode root) {
        return OpenVexParser.parse(root);
    }

    public static ParsedVexDocument cycloneDx(JsonNode root) {
        return CycloneDxVexParser.parse(root);
    }

    public static ParsedVexDocument csaf(JsonNode root, VexProperties properties) {
        return CsafVexParser.parse(root, properties);
    }

}
