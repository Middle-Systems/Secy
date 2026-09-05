package net.jdesive.secy.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * The outbound HTTP client the feed services use to pull NVD, EPSS and KEV.
 *
 * <p>They each used to {@code new RestTemplate()} inside {@code ingest()}, which meant no timeouts
 * and — more to the point — no way to exercise an ingest without reaching cisa.gov, first.org or
 * nvd.nist.gov. Injecting one bean makes the transport stubbable
 * ({@code MockRestServiceServer.bindTo(restTemplate)}) and gives every feed the same timeouts.
 */
@Configuration
public class HttpClientConfig {

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(30))
                // Feed pages are large and NVD in particular is slow; be patient, but not forever.
                .setReadTimeout(Duration.ofMinutes(2))
                .build();
    }

}
