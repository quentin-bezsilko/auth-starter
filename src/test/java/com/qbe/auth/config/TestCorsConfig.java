package com.qbe.auth.config;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

class TestCorsConfig {

    private UrlBasedCorsConfigurationSource source;

    @BeforeEach
    void setUp() {
        CorsConfig corsConfig = new CorsConfig();
        source = corsConfig.corsConfigurationSource();
    }

    @Test
    void shouldConfigureCorsForAllPaths() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/auth/login");

        CorsConfiguration configuration = source.getCorsConfiguration(request);
        assertNotNull(configuration);
    }

    @Test
    void shouldAllowAngularLocalhostOrigin() {
        CorsConfiguration configuration = getCorsConfiguration();
        assertEquals(List.of("http://localhost:4200"), configuration.getAllowedOrigins());
    }

    @Test
    void shouldAllowExpectedHttpMethods() {
        CorsConfiguration configuration = getCorsConfiguration();
        assertEquals(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"), configuration.getAllowedMethods());
    }

    @Test
    void shouldAllowExpectedHeaders() {
        CorsConfiguration configuration = getCorsConfiguration();
        assertEquals(List.of("Authorization", "Content-Type"), configuration.getAllowedHeaders());
    }

    @Test
    void shouldAllowCredentials() {
        CorsConfiguration configuration = getCorsConfiguration();
        assertTrue(configuration.getAllowCredentials());
    }

    private CorsConfiguration getCorsConfiguration() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/auth/login");

        CorsConfiguration configuration = source.getCorsConfiguration(request);
        assertNotNull(configuration);
        return configuration;
    }
}
