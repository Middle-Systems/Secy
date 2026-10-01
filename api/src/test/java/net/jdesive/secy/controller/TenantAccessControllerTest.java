package net.jdesive.secy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.entity.Role;
import net.jdesive.secy.persistence.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M1k's T3 — see ROADMAP.md's M1k section 10. Every "admin" account here is promoted to the global
 * {@code ADMIN} role directly via the repository ({@link #promoteToAdmin}) rather than relying on
 * M0's "first registered account becomes ADMIN" bootstrap rule — the H2 database is shared by every
 * {@code @SpringBootTest} context in the run, and a non-transactional test class elsewhere may have
 * already left a committed account behind, which would silently make that rule not fire here.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class TenantAccessControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AppUserRepository userRepository;

    @Test
    void adminSeesSecurityEngineerDefaultAndPlainUserToo() throws Exception {
        String adminToken = registerAndLogin("t3-admin@example.com", "correct-horse-battery", "T3 Admin");
        promoteToAdmin("t3-admin@example.com");
        String userToken = registerAndLogin("t3-user@example.com", "correct-horse-battery", "T3 User");

        mockMvc.perform(get("/me/access").header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.member").value(true))
                .andExpect(jsonPath("$.tenantAdmin").value(true))
                .andExpect(jsonPath("$.tenantAdminSource").value("GLOBAL_ADMIN"))
                .andExpect(jsonPath("$.defaultView").value("SECURITY_ENGINEER"));

        mockMvc.perform(get("/me/access").header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantAdmin").value(false))
                .andExpect(jsonPath("$.roles[0]").value("SECURITY_ENGINEER"));
    }

    @Test
    void plainUserPatchingSomeoneElseIsForbidden() throws Exception {
        String adminToken = registerAndLogin("t3-admin2@example.com", "correct-horse-battery", "T3 Admin2");
        promoteToAdmin("t3-admin2@example.com");
        String userToken = registerAndLogin("t3-user2@example.com", "correct-horse-battery", "T3 User2");

        mockMvc.perform(patch("/tenant/members/" + userId(adminToken, "t3-admin2@example.com"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                        .content(objectMapper.writeValueAsString(Map.of("tenantAdmin", true))))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminPatchRolesTakeEffectImmediatelyOnTheSameToken() throws Exception {
        String adminToken = registerAndLogin("t3-admin3@example.com", "correct-horse-battery", "T3 Admin3");
        promoteToAdmin("t3-admin3@example.com");
        String userToken = registerAndLogin("t3-user3@example.com", "correct-horse-battery", "T3 User3");
        String userId = userId(userToken, "t3-user3@example.com");

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("roles", java.util.List.of("SOFTWARE_ENGINEER")))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("SOFTWARE_ENGINEER"));

        // Same token, no re-login: GET /me/access reflects the change immediately.
        mockMvc.perform(get("/me/access").header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("SOFTWARE_ENGINEER"))
                .andExpect(jsonPath("$.defaultView").value("SOFTWARE_ENGINEER"));
    }

    @Test
    void rolesAndResetBothSetIsBadRequest() throws Exception {
        String adminToken = registerAndLogin("t3-admin4@example.com", "correct-horse-battery", "T3 Admin4");
        promoteToAdmin("t3-admin4@example.com");
        String userToken = registerAndLogin("t3-user4@example.com", "correct-horse-battery", "T3 User4");
        String userId = userId(userToken, "t3-user4@example.com");

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "roles", java.util.List.of("SOFTWARE_ENGINEER"), "resetRolesToDefault", true))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void emptyBodyIsBadRequest() throws Exception {
        String adminToken = registerAndLogin("t3-admin5@example.com", "correct-horse-battery", "T3 Admin5");
        promoteToAdmin("t3-admin5@example.com");
        String userToken = registerAndLogin("t3-user5@example.com", "correct-horse-battery", "T3 User5");
        String userId = userId(userToken, "t3-user5@example.com");

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unknownRoleStringIsBadRequest() throws Exception {
        String adminToken = registerAndLogin("t3-admin6@example.com", "correct-horse-battery", "T3 Admin6");
        promoteToAdmin("t3-admin6@example.com");
        String userToken = registerAndLogin("t3-user6@example.com", "correct-horse-battery", "T3 User6");
        String userId = userId(userToken, "t3-user6@example.com");

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content("{\"roles\":[\"NOT_A_ROLE\"]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void nonMemberUserIdIs404() throws Exception {
        String adminToken = registerAndLogin("t3-admin7@example.com", "correct-horse-battery", "T3 Admin7");
        promoteToAdmin("t3-admin7@example.com");

        mockMvc.perform(patch("/tenant/members/" + java.util.UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("tenantAdmin", true))))
                .andExpect(status().isNotFound());
    }

    @Test
    void grantedTenantAdminCanThenPatchAThirdUser() throws Exception {
        String adminToken = registerAndLogin("t3-admin8@example.com", "correct-horse-battery", "T3 Admin8");
        promoteToAdmin("t3-admin8@example.com");
        String user2Token = registerAndLogin("t3-user8-2@example.com", "correct-horse-battery", "T3 User8-2");
        String user3Token = registerAndLogin("t3-user8-3@example.com", "correct-horse-battery", "T3 User8-3");
        String user2Id = userId(user2Token, "t3-user8-2@example.com");
        String user3Id = userId(user3Token, "t3-user8-3@example.com");

        mockMvc.perform(patch("/tenant/members/" + user2Id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("tenantAdmin", true))))
                .andExpect(status().isOk());

        mockMvc.perform(patch("/tenant/members/" + user3Id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + user2Token)
                        .content(objectMapper.writeValueAsString(Map.of("roles", java.util.List.of("LEADERSHIP")))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("LEADERSHIP"));
    }

    @Test
    void resetRolesToDefaultBringsBackTheDefault() throws Exception {
        String adminToken = registerAndLogin("t3-admin9@example.com", "correct-horse-battery", "T3 Admin9");
        promoteToAdmin("t3-admin9@example.com");
        String userToken = registerAndLogin("t3-user9@example.com", "correct-horse-battery", "T3 User9");
        String userId = userId(userToken, "t3-user9@example.com");

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("roles", java.util.List.of("LEADERSHIP")))))
                .andExpect(status().isOk());

        mockMvc.perform(patch("/tenant/members/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .content(objectMapper.writeValueAsString(Map.of("resetRolesToDefault", true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("SECURITY_ENGINEER"));
    }

    @Test
    @WithMockUser
    void withMockUserPatchIsForbidden() throws Exception {
        mockMvc.perform(patch("/tenant/members/" + java.util.UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("tenantAdmin", true))))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser
    void withMockUserGetMyAccessIsUnauthorized() throws Exception {
        mockMvc.perform(get("/me/access")).andExpect(status().isUnauthorized());
    }

    @Test
    void tenantMembersShowsEffectiveFields() throws Exception {
        String adminToken = registerAndLogin("t3-admin10@example.com", "correct-horse-battery", "T3 Admin10");
        promoteToAdmin("t3-admin10@example.com");

        mockMvc.perform(get("/tenant/members").header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].tenantAdmin").exists())
                .andExpect(jsonPath("$[0].rolesSource").exists());
    }

    private String userId(String token, String email) throws Exception {
        MvcResult result = mockMvc.perform(get("/tenant/members").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        for (JsonNode node : body) {
            if (node.get("email").asText().equalsIgnoreCase(email)) {
                return node.get("userId").asText();
            }
        }
        throw new AssertionError("no member found with email " + email);
    }

    private void promoteToAdmin(String email) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.setRole(Role.ADMIN);
        userRepository.save(user);
    }

    private String registerAndLogin(String email, String password, String displayName) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", email, "password", password, "displayName", displayName))))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("token").asText();
    }

}
