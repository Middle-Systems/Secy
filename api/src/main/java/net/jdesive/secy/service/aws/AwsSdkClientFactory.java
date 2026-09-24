package net.jdesive.secy.service.aws;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.inspector2.Inspector2Client;
import software.amazon.awssdk.services.lambda.LambdaClient;

/**
 * The real {@link AwsClientFactory}: one instance-wide access key / secret key pair (the same
 * "one credential per provider, never per connector" choice {@code SourceConnector}'s class Javadoc
 * documents for GitHub), wrapped in a {@link StaticCredentialsProvider} and handed to a freshly built
 * client per call.
 *
 * <p>Deliberately not itself a {@code @Component} — {@code AwsConfig} constructs it once with the
 * {@code @Value}-read credentials and publishes it as the {@link AwsClientFactory} bean, so this
 * class never touches Spring annotations and stays trivially constructible in a plain unit test if
 * one ever needs the real client-building logic rather than a mock.
 *
 * <p>Blank credentials are not pre-validated in the constructor, and the {@link AwsCredentialsProvider}
 * is built lazily in {@link #credentialsProvider()} rather than once up front — {@code
 * AwsBasicCredentials.create} itself throws immediately on a blank access key, and building it eagerly
 * here means that exception surfaces from the {@code @Bean} method in {@code AwsConfig}, which Spring
 * evaluates at application startup: every install without AWS credentials configured (the default —
 * this connector is opt-in) would fail to start at all, not just fail to sync AWS. Deferred like this,
 * a blank credential pair only fails when an AWS sync actually runs and asks for a client, exactly the
 * way {@code GitHubApiClient} lets a blank token fail naturally at the first real call rather than
 * inventing a different error message for it.
 */
final class AwsSdkClientFactory implements AwsClientFactory {

    private final String accessKeyId;
    private final String secretAccessKey;

    AwsSdkClientFactory(String accessKeyId, String secretAccessKey) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
    }

    private AwsCredentialsProvider credentialsProvider() {
        return StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey));
    }

    @Override
    public Ec2Client ec2Client(Region region) {
        return Ec2Client.builder().region(region).credentialsProvider(credentialsProvider()).build();
    }

    @Override
    public EcrClient ecrClient(Region region) {
        return EcrClient.builder().region(region).credentialsProvider(credentialsProvider()).build();
    }

    @Override
    public LambdaClient lambdaClient(Region region) {
        return LambdaClient.builder().region(region).credentialsProvider(credentialsProvider()).build();
    }

    @Override
    public Inspector2Client inspector2Client(Region region) {
        return Inspector2Client.builder().region(region).credentialsProvider(credentialsProvider()).build();
    }

}
