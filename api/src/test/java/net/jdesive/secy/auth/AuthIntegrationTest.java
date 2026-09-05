package net.jdesive.secy.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end pass over the auth surface against a real (H2-backed) application context:
 * a protected endpoint refuses anonymous callers, registration bootstraps the first admin,
 * login mints a token, and that token opens both the protected endpoint and /auth/me.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthIntegrationTest {

    private static final String EMAIL = "first.admin@example.com";
    private static final String PASSWORD = "correct-horse-battery";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AppUserRepository users;

    @BeforeEach
    void clearAccounts() {
        // The "first account becomes ADMIN" rule is a function of the table being empty, and the
        // H2 database is shared by every context in the run — start from a known state.
        users.deleteAll();
    }

    @Test
    void protectedEndpointRejectsAnonymousCallers() throws Exception {
        mockMvc.perform(get("/products"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void meRejectsAnonymousCallers() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void firstRegisteredAccountBecomesAdminAndTheSecondDoesNot() throws Exception {
        MvcResult first = register(EMAIL, PASSWORD, "First Admin")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.role").value("ADMIN"))
                .andExpect(jsonPath("$.user.email").value(EMAIL))
                .andExpect(jsonPath("$.user.displayName").value("First Admin"))
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                // The hash must have no path into a response body.
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist())
                .andReturn();

        assertThat(first.getResponse().getContentAsString()).doesNotContain(PASSWORD);

        register("second@example.com", PASSWORD, null)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.role").value("USER"));
    }

    @Test
    void registeringTheSameEmailTwiceConflicts() throws Exception {
        register(EMAIL, PASSWORD, null).andExpect(status().isCreated());
        register(EMAIL, PASSWORD, null).andExpect(status().isConflict());
    }

    @Test
    void registrationRejectsAnInvalidBody() throws Exception {
        register("not-an-email", PASSWORD, null).andExpect(status().isBadRequest());
        register("valid@example.com", "short", null).andExpect(status().isBadRequest());
    }

    @Test
    void loginReturnsATokenThatOpensProtectedEndpointsAndRoundTripsThroughMe() throws Exception {
        register(EMAIL, PASSWORD, "First Admin").andExpect(status().isCreated());

        MvcResult login = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();

        JsonNode body = objectMapper.readTree(login.getResponse().getContentAsString());
        String token = body.get("token").asText();
        // Three dot-separated segments — a compact JWS, not an opaque handle.
        assertThat(token.split("\\.")).hasSize(3);

        mockMvc.perform(get("/products").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(get("/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.id").value(body.get("user").get("id").asText()))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void loginRejectsAWrongPasswordAndAnUnknownAccount() throws Exception {
        register(EMAIL, PASSWORD, null).andExpect(status().isCreated());

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", EMAIL, "password", "wrong-password"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "nobody@example.com", "password", PASSWORD))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void aGarbageTokenIsTreatedAsAnonymous() throws Exception {
        mockMvc.perform(get("/products").header(HttpHeaders.AUTHORIZATION, "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theOpenApiDocsStayAnonymous() throws Exception {
        mockMvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
        mockMvc.perform(get("/auth/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.registrationEnabled").value(true));
    }

    private org.springframework.test.web.servlet.ResultActions register(String email,
                                                                       String password,
                                                                       String displayName) throws Exception {
        var payload = new java.util.HashMap<String, Object>();
        payload.put("email", email);
        payload.put("password", password);
        if (displayName != null) {
            payload.put("displayName", displayName);
        }
        return mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(payload)));
    }
}
