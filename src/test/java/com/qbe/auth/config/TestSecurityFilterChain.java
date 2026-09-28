package com.qbe.auth.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
        properties = {
            "app.security.keys.private-key=classpath:certs/private-key.pem",
            "app.security.keys.public-key=classpath:certs/public-key.pem"
        })
@AutoConfigureMockMvc
class TestSecurityFilterChain {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldAllowLoginEndpointWithoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/login")).andExpect(result -> {
            int status = result.getResponse().getStatus();

            // Le point important :
            // Spring Security ne doit PAS renvoyer 401/403.
            if (status == 401 || status == 403) {
                throw new AssertionError("Login endpoint should be public, status=" + status);
            }
        });
    }

    @Test
    void shouldAllowRefreshEndpointWithoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/refresh")).andExpect(result -> {
            int status = result.getResponse().getStatus();
            if (status == 401 || status == 403) {
                throw new AssertionError("Refresh endpoint should be public, status=" + status);
            }
        });
    }

    @Test
    void shouldAllowLogoutEndpointWithoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/logout")).andExpect(result -> {
            int status = result.getResponse().getStatus();
            if (status == 401 || status == 403) {
                throw new AssertionError("Logout endpoint should be public, status=" + status);
            }
        });
    }

    @Test
    void shouldDenyUnknownEndpoint() throws Exception {
        mockMvc.perform(get("/private")).andExpect(status().isForbidden());
    }
}
