package net.jdesive.secy.service.aws;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.inspector2.Inspector2Client;
import software.amazon.awssdk.services.lambda.LambdaClient;

/**
 * Builds the four AWS SDK v2 clients {@link AwsSyncService} needs, region-scoped.
 *
 * <h2>Why a factory and not four {@code @Bean} clients</h2>
 *
 * <p>Unlike {@code GitHubApiClient}'s single instance-wide {@code RestTemplate}, an AWS SDK client is
 * bound to one {@link Region} at construction time — and {@code SourceConnector.scope} (the region to
 * enumerate) is a per-row value, not something known at bean-creation time. A singleton
 * {@code Ec2Client} bean would only ever work for one hardcoded region. This factory defers client
 * construction to {@link AwsSyncService#sync}, once the connector (and therefore its region) is in
 * hand, and builds a fresh set of clients per sync rather than caching them — simplicity over a
 * micro-optimization that would need its own eviction policy for no real benefit here.
 *
 * <h2>Why an interface at all</h2>
 *
 * <p>This is the seam that makes {@code AwsSyncService} unit-testable without live AWS credentials or
 * network access: tests inject a factory that hands back Mockito mocks of {@link Ec2Client}/
 * {@link EcrClient}/{@link LambdaClient}/{@link Inspector2Client} instead of real ones. Production
 * wiring lives in {@code AwsConfig}, which reads the instance-wide credentials via {@code @Value} and
 * publishes the real implementation as a bean — {@code AwsSyncService} itself never touches
 * {@code @Value} or {@code StaticCredentialsProvider}.
 */
public interface AwsClientFactory {

    Ec2Client ec2Client(Region region);

    EcrClient ecrClient(Region region);

    LambdaClient lambdaClient(Region region);

    Inspector2Client inspector2Client(Region region);

}
