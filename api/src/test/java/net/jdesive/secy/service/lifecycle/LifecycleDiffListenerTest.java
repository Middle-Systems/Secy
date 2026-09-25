package net.jdesive.secy.service.lifecycle;

import net.jdesive.secy.events.SbomUploadedEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * {@link LifecycleDiffListener}: a diff failure is caught and logged, never rethrown — the SBOM
 * upload it rode in on already committed by the time this listener runs, and a diffing bug must never
 * turn an already-successful ingestion into a failed job. No Spring context needed; the service is
 * mocked.
 */
@ExtendWith(MockitoExtension.class)
class LifecycleDiffListenerTest {

    @Mock
    private LifecycleDiffService lifecycleDiffService;

    @Test
    void aRuntimeExceptionFromTheDiffServiceIsSwallowedNotRethrown() {
        UUID sbomId = UUID.randomUUID();
        given(lifecycleDiffService.runForSbom(any())).willThrow(new RuntimeException("boom"));

        LifecycleDiffListener listener = new LifecycleDiffListener(lifecycleDiffService);

        assertThatCode(() -> listener.onSbomUploaded(new SbomUploadedEvent(sbomId))).doesNotThrowAnyException();

        verify(lifecycleDiffService).runForSbom(sbomId);
    }

}
