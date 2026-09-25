package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.VexPrecedenceConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** {@code GET}/{@code PUT /vex/settings/precedence} — default, a valid update, and an invalid one. */
@SpringBootTest
@AutoConfigureMockMvc
class VexPrecedenceSettingsTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VexPrecedenceConfigRepository vexPrecedenceConfigRepository;

    @BeforeEach
    void seed() {
        vexPrecedenceConfigRepository.deleteAll();
    }

    @Test
    @WithMockUser
    void defaultsToTenantOverVendorWhenUnconfigured() throws Exception {
        mockMvc.perform(get("/vex/settings/precedence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policy").value("TENANT_OVER_VENDOR"))
                .andExpect(jsonPath("$.alertsEvaluated").doesNotExist());
    }

    @Test
    @WithMockUser
    void puttingAValidPolicyPersistsItAndReportsReconcileCounts() throws Exception {
        mockMvc.perform(put("/vex/settings/precedence")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policy\": \"VENDOR_OVER_TENANT\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policy").value("VENDOR_OVER_TENANT"))
                .andExpect(jsonPath("$.alertsEvaluated").value(0))
                .andExpect(jsonPath("$.alertsChanged").value(0));

        mockMvc.perform(get("/vex/settings/precedence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policy").value("VENDOR_OVER_TENANT"));
    }

    @Test
    @WithMockUser
    void puttingAnInvalidPolicyIs400() throws Exception {
        mockMvc.perform(put("/vex/settings/precedence")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policy\": \"NONSENSE\"}"))
                .andExpect(status().isBadRequest());
    }

}
