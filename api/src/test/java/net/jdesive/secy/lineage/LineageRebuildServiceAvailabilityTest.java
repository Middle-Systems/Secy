package net.jdesive.secy.lineage;

import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.TenantRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link LineageRebuildService#isAvailable()} / {@link LineageRebuildService#ingest} when
 * {@code secy.lineage.enabled=false} or no writer bean exists — plain construction, no Spring
 * context needed since these paths never touch the reader or the tenant repository.
 */
class LineageRebuildServiceAvailabilityTest {

    private final LineageSourceReader reader = mock(LineageSourceReader.class);

    private final TenantRepository tenantRepository = mock(TenantRepository.class);

    @Test
    void notAvailableWhenDisabledEvenWithAWriter() {
        LineageProperties disabled = new LineageProperties();
        disabled.setEnabled(false);
        ObjectProvider<LineageGraphWriter> provider = providerOf(mock(LineageGraphWriter.class));

        LineageRebuildService service = new LineageRebuildService(reader, tenantRepository, provider, disabled);

        assertThat(service.isAvailable()).isFalse();
        assertThatThrownBy(() -> service.ingest(JobProgress.NOOP)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void notAvailableWhenEnabledButNoWriterBeanExists() {
        LineageProperties enabled = new LineageProperties();
        enabled.setEnabled(true);
        ObjectProvider<LineageGraphWriter> provider = providerOf(null);

        LineageRebuildService service = new LineageRebuildService(reader, tenantRepository, provider, enabled);

        assertThat(service.isAvailable()).isFalse();
        assertThatThrownBy(() -> service.ingest(JobProgress.NOOP)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void availableWhenEnabledAndAWriterExists() {
        LineageProperties enabled = new LineageProperties();
        enabled.setEnabled(true);
        ObjectProvider<LineageGraphWriter> provider = providerOf(mock(LineageGraphWriter.class));

        LineageRebuildService service = new LineageRebuildService(reader, tenantRepository, provider, enabled);

        assertThat(service.isAvailable()).isTrue();
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<LineageGraphWriter> providerOf(LineageGraphWriter writer) {
        ObjectProvider<LineageGraphWriter> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(writer);
        return provider;
    }

}
