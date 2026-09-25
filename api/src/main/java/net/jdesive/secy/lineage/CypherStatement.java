package net.jdesive.secy.lineage;

import java.util.Map;

/**
 * One Cypher statement plus its bind parameters, ready to be wrapped by {@link AgeSql#wrap} and
 * executed by {@link AgeLineageGraphWriter}.
 *
 * <p>{@code cypher} never contains a literal data value — every value flows through {@code params}
 * — so the statement text is safe to log and stays identical across runs with different data
 * ({@link CypherRendererTest} asserts this directly).
 */
public record CypherStatement(String cypher, Map<String, Object> params) {
}
