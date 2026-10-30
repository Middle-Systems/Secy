package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.ProductTagConfigRepository;
import net.jdesive.secy.persistence.entity.ProductTagConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET}/{@code PUT /settings/product-tagging} (M1a): default response shape, update-then-
 * reflect, 400 on a bad key, and the same auth requirement every other protected endpoint has (see
 * {@code SecurityConfig} — everything outside {@code /auth/**}/{@code /actuator/health}/OpenAPI
 * docs needs a bearer token, same as {@code /products}).
 */
@SpringBootTest
@AutoConfigureMockMvc
class ProductTaggingSettingsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductTagConfigRepository productTagConfigRepository;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run — every test class
        // touching ProductTagConfigRepository must clear it, or a custom key leaks between classes.
        productTagConfigRepository.deleteAll();
    }

    @Test
    @WithMockUser
    void getDefaultsToSecyProductWithNoConfigRow() throws Exception {
        mockMvc.perform(get("/settings/product-tagging"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tagKey").value(ProductTagConfig.DEFAULT_TAG_KEY))
                .andExpect(jsonPath("$.defaultTagKey").value(ProductTagConfig.DEFAULT_TAG_KEY))
                .andExpect(jsonPath("$.usingDefault").value(true));
    }

    @Test
    @WithMockUser
    void putUpdatesTheKeyAndAGetReflectsIt() throws Exception {
        mockMvc.perform(put("/settings/product-tagging")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("tagKey", "team:owner"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tagKey").value("team:owner"))
                .andExpect(jsonPath("$.usingDefault").value(false));

        mockMvc.perform(get("/settings/product-tagging"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tagKey").value("team:owner"));
    }

    @Test
    @WithMockUser
    void putRejectsABadKeyWith400() throws Exception {
        mockMvc.perform(put("/settings/product-tagging")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("tagKey", "has space"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void bothEndpointsRequireAuthentication() throws Exception {
        mockMvc.perform(get("/settings/product-tagging")).andExpect(status().isUnauthorized());
        mockMvc.perform(put("/settings/product-tagging")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("tagKey", "team:owner"))))
                .andExpect(status().isUnauthorized());
    }
}
