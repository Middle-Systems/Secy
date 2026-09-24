package net.jdesive.secy.service.aws;

/**
 * The single public door into this package's {@link AwsClientFactory} implementation, so
 * {@code AwsConfig} (in {@code net.jdesive.secy.config}) can build the real one without
 * {@link AwsSdkClientFactory} itself needing to be public — it is wiring, not something anything
 * else in the codebase should construct directly or depend on the shape of.
 */
public final class AwsClientFactories {

    private AwsClientFactories() {
    }

    /** The real, SDK-backed {@link AwsClientFactory}, credentialed with one instance-wide key pair. */
    public static AwsClientFactory real(String accessKeyId, String secretAccessKey) {
        return new AwsSdkClientFactory(accessKeyId, secretAccessKey);
    }

}
