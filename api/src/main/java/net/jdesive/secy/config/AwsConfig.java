package net.jdesive.secy.config;

import net.jdesive.secy.service.aws.AwsClientFactory;
import net.jdesive.secy.service.aws.AwsClientFactories;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the instance-wide AWS credentials ({@code secy.aws.access-key-id} /
 * {@code secy.aws.secret-access-key} — see {@code application.properties}) into an
 * {@link AwsClientFactory} bean, the same "read the env var here, hand a built collaborator to the
 * sync service" shape {@code GitHubApiClient} uses for {@code secy.github.token}, just one level
 * removed: {@code AwsSyncService} needs a <em>factory</em>, not a single client, because the region a
 * sync targets varies per {@code SourceConnector} row (see {@link AwsClientFactory}'s Javadoc).
 */
@Configuration
public class AwsConfig {

    @Bean
    public AwsClientFactory awsClientFactory(
            @Value("${secy.aws.access-key-id:}") String accessKeyId,
            @Value("${secy.aws.secret-access-key:}") String secretAccessKey) {
        return AwsClientFactories.real(accessKeyId, secretAccessKey);
    }

}
