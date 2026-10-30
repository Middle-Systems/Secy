package net.jdesive.secy.model.component;

import net.jdesive.secy.persistence.entity.DependencyDepth;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M1l (ROADMAP.md — "Dependency graph preserved"): {@link DependencyGraphAnalyzer}'s cycle-safe BFS
 * classification, pinned against the plan's own worked examples.
 */
class DependencyGraphAnalyzerTest {

    @Test
    void directAndTransitiveChain() {
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("root", "a"), new DependencyEdge("a", "b"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("b"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        DependencyGraphAnalyzer.Position aPos = analysis.positionOf("a");
        assertThat(aPos.depth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(aPos.distance()).isEqualTo(1);
        assertThat(aPos.path()).containsExactly("root", "a");

        DependencyGraphAnalyzer.Position bPos = analysis.positionOf("b");
        assertThat(bPos.depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(bPos.distance()).isEqualTo(2);
        assertThat(bPos.path()).containsExactly("root", "a", "b");
    }

    @Test
    void diamondTakesTheFirstDiscoveredShortestPath() {
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("root", "a"), new DependencyEdge("root", "b"),
                new DependencyEdge("a", "c"), new DependencyEdge("b", "c"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("b"), comp("c"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        DependencyGraphAnalyzer.Position cPos = analysis.positionOf("c");
        assertThat(cPos.depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(cPos.distance()).isEqualTo(2);
        assertThat(cPos.path()).containsExactly("root", "a", "c");
    }

    @Test
    void directWinsEvenWhenALongerPathAlsoExists() {
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("root", "a"), new DependencyEdge("root", "c"), new DependencyEdge("a", "c"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("c"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        DependencyGraphAnalyzer.Position cPos = analysis.positionOf("c");
        assertThat(cPos.depth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(cPos.distance()).isEqualTo(1);
    }

    @Test
    void cycleBackToAMidGraphNodeTerminates() {
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("root", "a"), new DependencyEdge("a", "b"),
                new DependencyEdge("b", "a"), new DependencyEdge("b", "c"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("b"), comp("c"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("a").depth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(analysis.positionOf("b").depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(analysis.positionOf("b").distance()).isEqualTo(2);
        assertThat(analysis.positionOf("c").depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(analysis.positionOf("c").distance()).isEqualTo(3);
    }

    @Test
    void cycleBackToTheRootTerminates() {
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("root", "a"), new DependencyEdge("a", "b"), new DependencyEdge("b", "root"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("b"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("a").depth()).isEqualTo(DependencyDepth.DIRECT);
        assertThat(analysis.positionOf("b").depth()).isEqualTo(DependencyDepth.TRANSITIVE);
    }

    @Test
    void unreachableIslandIsUnknownNotTransitive() {
        List<DependencyEdge> edges = List.of(new DependencyEdge("root", "a"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("island"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("island").depth()).isEqualTo(DependencyDepth.UNKNOWN);
        assertThat(analysis.positionOf("island").distance()).isNull();
        assertThat(analysis.positionOf("island").path()).isNull();
    }

    @Test
    void emptyRootRefsMakesEverythingUnknown() {
        List<DependencyEdge> edges = List.of(new DependencyEdge("root", "a"));
        List<NormalizedComponent> components = List.of(comp("a"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of(), edges, components);

        assertThat(analysis.positionOf("a").depth()).isEqualTo(DependencyDepth.UNKNOWN);
    }

    @Test
    void nullBomRefIsUnknown() {
        DependencyGraphAnalyzer.Analysis analysis =
                DependencyGraphAnalyzer.analyze(Set.of("root"), List.of(new DependencyEdge("root", "a")), List.of());

        assertThat(analysis.positionOf(null).depth()).isEqualTo(DependencyDepth.UNKNOWN);
    }

    @Test
    void duplicateComponentRefsAreUnknownForBoth() {
        List<DependencyEdge> edges = List.of(new DependencyEdge("root", "a"));
        List<NormalizedComponent> components = List.of(comp("a"), comp("a"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("a").depth()).isEqualTo(DependencyDepth.UNKNOWN);
    }

    @Test
    void refEqualToRootRefIsUnknown() {
        List<DependencyEdge> edges = List.of(new DependencyEdge("root", "root"));
        List<NormalizedComponent> components = List.of(comp("root"));

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("root").depth()).isEqualTo(DependencyDepth.UNKNOWN);
    }

    @Test
    void multiRootBfsDependencyOfEitherRootIsDirect() {
        List<DependencyEdge> edges = List.of(new DependencyEdge("root2", "a"));
        List<NormalizedComponent> components = List.of(comp("a"));

        DependencyGraphAnalyzer.Analysis analysis =
                DependencyGraphAnalyzer.analyze(Set.of("root1", "root2"), edges, components);

        assertThat(analysis.positionOf("a").depth()).isEqualTo(DependencyDepth.DIRECT);
    }

    @Test
    void chainOf40HonoursTheMaxPathHopsBoundaryExactly() {
        List<DependencyEdge> edges = new ArrayList<>();
        List<NormalizedComponent> components = new ArrayList<>();
        String prev = "root";
        for (int i = 1; i <= 40; i++) {
            String ref = "c" + i;
            edges.add(new DependencyEdge(prev, ref));
            components.add(comp(ref));
            prev = ref;
        }

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        DependencyGraphAnalyzer.Position c32 = analysis.positionOf("c32");
        assertThat(c32.distance()).isEqualTo(32);
        assertThat(c32.path()).isNotNull();
        assertThat(c32.path()).hasSize(33); // root + 32 hops

        DependencyGraphAnalyzer.Position c40 = analysis.positionOf("c40");
        assertThat(c40.depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(c40.distance()).isEqualTo(40);
        assertThat(c40.path()).isNull();
    }

    @Test
    void tenThousandLongChainFinishesWithoutStackOverflow() {
        List<DependencyEdge> edges = new ArrayList<>();
        List<NormalizedComponent> components = new ArrayList<>();
        String prev = "root";
        for (int i = 1; i <= 10_000; i++) {
            String ref = "c" + i;
            edges.add(new DependencyEdge(prev, ref));
            components.add(comp(ref));
            prev = ref;
        }

        DependencyGraphAnalyzer.Analysis analysis = DependencyGraphAnalyzer.analyze(Set.of("root"), edges, components);

        assertThat(analysis.positionOf("c10000").depth()).isEqualTo(DependencyDepth.TRANSITIVE);
        assertThat(analysis.positionOf("c10000").distance()).isEqualTo(10_000);
    }

    /* ------------------------------------------------------------------ */
    /* DependencyEdgeCollector overflow                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void collectorOverflowDiscardsTheWholeGraph() {
        DependencyEdgeCollector collector = new DependencyEdgeCollector(3);
        collector.add("a", "b");
        collector.add("b", "c");
        collector.add("c", "d");
        assertThat(collector.overflowed()).isFalse();
        assertThat(collector.edges()).hasSize(3);

        collector.add("d", "e");
        assertThat(collector.overflowed()).isTrue();
        assertThat(collector.edges()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static NormalizedComponent comp(String bomRef) {
        return NormalizedComponent.builder().bomRef(bomRef).name(bomRef).build();
    }

}
