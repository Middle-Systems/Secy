package net.jdesive.secy.correlation;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CPE 2.3 parser that replaced {@code criteria.split(":")[5]}.
 *
 * <p>Each test here is a shape the naive split got wrong, and each wrong answer was either a false
 * positive on every component in the estate or a silently dropped match.
 */
class Cpe23Test {

    @Test
    void parsesTheThirteenFieldsOfATypicalNvdRow() {
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.part()).isEqualTo("a");
        assertThat(cpe.vendor()).isEqualTo("apache");
        assertThat(cpe.product()).isEqualTo("log4j");
        assertThat(cpe.version()).isEqualTo("2.14.1");
        assertThat(cpe.update()).isEqualTo("*");
        assertThat(cpe.isApplication()).isTrue();
        assertThat(cpe.hasConcreteVersion()).isTrue();
    }

    @Test
    void anEscapedColonDoesNotShiftEveryLaterField() {
        // The split(":") bug in one line: the version here contains an escaped colon, so a naive
        // split reads "1.0\" as the version and every field after it belongs to its neighbour.
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:vendor:product:1.0\\:beta:sp1:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.version()).isEqualTo("1.0:beta");
        assertThat(cpe.update()).isEqualTo("sp1");
        assertThat(cpe.product()).isEqualTo("product");
    }

    @Test
    void escapedSpecialCharactersAreUnescaped() {
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:vendor:my\\-product:1.0:*:*:*:*:*:*:*").orElseThrow();
        assertThat(cpe.product()).isEqualTo("my-product");
    }

    @Test
    void aWildcardVersionIsNotAVersion() {
        // The single most common modern row, and the one the old code read as a literal version
        // "*" that compared below everything — so every component matched every CVE.
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.isAnyVersion()).isTrue();
        assertThat(cpe.hasConcreteVersion()).isFalse();
    }

    @Test
    void theNaValueIsAlsoNotAVersion() {
        Cpe23 cpe = Cpe23.parse("cpe:2.3:o:vendor:firmware:-:*:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.isAnyVersion()).isTrue();
        assertThat(cpe.isApplication()).isFalse();
        assertThat(cpe.part()).isEqualTo("o");
    }

    @Test
    void namesAreCaseInsensitive() {
        Cpe23 cpe = Cpe23.parse("CPE:2.3:A:Apache:Log4J:2.14.1:*:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.vendor()).isEqualTo("apache");
        assertThat(cpe.product()).isEqualTo("log4j");
        assertThat(cpe.productMatches("LOG4J")).isTrue();
        assertThat(cpe.vendorMatches("APACHE")).isTrue();
    }

    @Test
    void aWildcardFieldMatchesAnyCandidate() {
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:*:log4j:*:*:*:*:*:*:*:*").orElseThrow();

        assertThat(cpe.vendorMatches("anyone")).isTrue();
        assertThat(cpe.productMatches("log4j")).isTrue();
        assertThat(cpe.productMatches("something-else")).isFalse();
    }

    @Test
    void aShortRowIsPaddedRatherThanRejected() {
        // Hand-written CPEs in fixtures and VEX documents routinely stop early. Refusing them would
        // drop real matches for no gain.
        Cpe23 cpe = Cpe23.parse("cpe:2.3:a:openssl:openssl:1.1.1f").orElseThrow();

        assertThat(cpe.product()).isEqualTo("openssl");
        assertThat(cpe.version()).isEqualTo("1.1.1f");
        assertThat(cpe.other()).isEqualTo("*");
    }

    @Test
    void anythingThatIsNotACpe23StringIsRejected() {
        assertThat(Cpe23.parse(null)).isEmpty();
        assertThat(Cpe23.parse("")).isEmpty();
        assertThat(Cpe23.parse("log4j-core")).isEmpty();
        // CPE 2.2 URI binding — a different format, not something to guess at.
        assertThat(Cpe23.parse("cpe:/a:apache:log4j:2.14.1")).isEmpty();
    }

    @Test
    void parsingIsTotalForTrailingBackslashes() {
        Optional<Cpe23> cpe = Cpe23.parse("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:\\");
        assertThat(cpe).isPresent();
    }

}
