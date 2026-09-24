package net.jdesive.secy.service.aws;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The regression this pins: {@code AwsConfig#awsClientFactory} is a {@code @Bean} method, which
 * Spring evaluates at application startup — so if building this class eagerly validates the
 * credentials, every install without {@code secy.aws.*} configured (the default; the connector is
 * opt-in) fails to start the whole application, not just the AWS connector. Blank credentials must
 * only fail when a client is actually requested.
 */
class AwsSdkClientFactoryTest {

    @Test
    void constructingWithBlankCredentialsDoesNotThrow() {
        assertThatCode(() -> new AwsSdkClientFactory("", "")).doesNotThrowAnyException();
    }

    @Test
    void requestingAClientWithBlankCredentialsFailsAtThatPointNotBefore() {
        AwsSdkClientFactory factory = new AwsSdkClientFactory("", "");

        assertThatThrownBy(() -> factory.ec2Client(Region.US_EAST_1))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Access key ID cannot be blank");
    }

}
