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
 * documents for GitHub), wrapped in a fresh {@link StaticCredentialsProvider} and handed to a
 * freshly built client per call.
 *
 * <p>Deliberately not itself a {@code @Component} — {@code AwsConfig} constructs it once with the
 * {@code @Value}-read credentials and publishes it as the {@link AwsClientFactory} bean, so this
 * class never touches Spring annotations and stays trivially constructible in a plain unit test if
 * one ever needs the real client-building logic rather than a mock.
 *
 * <p>Blank credentials are not pre-validated here — a blank access key / secret key pair is handed to
 * {@link StaticCredentialsProvider} as-is, and the first real AWS call fails with the SDK's own
 * authentication error, exactly the way {@code GitHubApiClient} lets a blank token fail naturally
 * rather than inventing a different error message for it.
 */
final class AwsSdkClientFactory implements AwsClientFactory {

    private final AwsCredentialsProvider credentialsProvider;

    AwsSdkClientFactory(String accessKeyId, String secretAccessKey) {
        this.credentialsProvider = StaticCredentialsProvider.create(
                AwsBasicCredentials.create(accessKeyId, secretAccessKey));
    }

    @Override
    public Ec2Client ec2Client(Region region) {
        return Ec2Client.builder().region(region).credentialsProvider(credentialsProvider).build();
    }

    @Override
    public EcrClient ecrClient(Region region) {
        return EcrClient.builder().region(region).credentialsProvider(credentialsProvider).build();
    }

    @Override
    public LambdaClient lambdaClient(Region region) {
        return LambdaClient.builder().region(region).credentialsProvider(credentialsProvider).build();
    }

    @Override
    public Inspector2Client inspector2Client(Region region) {
        return Inspector2Client.builder().region(region).credentialsProvider(credentialsProvider).build();
    }

}
