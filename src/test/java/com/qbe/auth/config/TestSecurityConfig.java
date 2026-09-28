package com.qbe.auth.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbe.auth.service.UserService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

class TestSecurityConfig {

    private static final String KEY_ID = "authstarter-key";

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig();
    }

    @Test
    void shouldCreateBCryptPasswordEncoder() {
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
        assertNotNull(passwordEncoder);
        assertInstanceOf(BCryptPasswordEncoder.class, passwordEncoder);
    }

    @Test
    void shouldEncodeAndMatchPassword() {
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        String rawPassword = "my-password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotNull(encodedPassword);
        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
        assertFalse(passwordEncoder.matches("wrong-password", encodedPassword));
    }

    @Test
    void shouldCreateAuthenticationProvider() {
        UserService userService = mock(UserService.class);
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        DaoAuthenticationProvider provider = securityConfig.authenticationProvider(userService, passwordEncoder);
        assertNotNull(provider);
    }

    @Test
    void shouldCreateAuthenticationManager() {
        UserService userService = mock(UserService.class);
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        DaoAuthenticationProvider provider = securityConfig.authenticationProvider(userService, passwordEncoder);
        AuthenticationManager authenticationManager = securityConfig.authenticationManager(provider);

        assertNotNull(authenticationManager);
        assertInstanceOf(ProviderManager.class, authenticationManager);
    }

    @Test
    void shouldCreateJwkSource() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        JWKSource<SecurityContext> source = securityConfig.jwkSource(publicKey, privateKey);
        assertNotNull(source);
    }

    @Test
    void shouldExposeRsaKeyWithExpectedKeyId() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        JWKSource<SecurityContext> source = securityConfig.jwkSource(publicKey, privateKey);

        JWKSelector selector =
                new JWKSelector(new JWKMatcher.Builder().keyID(KEY_ID).build());

        List<JWK> keys = source.get(selector, null);

        assertNotNull(keys);
        assertEquals(1, keys.size());
        assertEquals(KEY_ID, keys.getFirst().getKeyID());
    }

    @Test
    void shouldCreateJwtEncoder() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        JWKSource<SecurityContext> source = securityConfig.jwkSource(publicKey, privateKey);
        JwtEncoder jwtEncoder = securityConfig.jwtEncoder(source);

        assertNotNull(jwtEncoder);
        assertInstanceOf(NimbusJwtEncoder.class, jwtEncoder);
    }

    @Test
    void shouldExposeRsaKeyWithPublicAndPrivateKey() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        JWKSource<SecurityContext> source = securityConfig.jwkSource(publicKey, privateKey);
        JWKSelector selector =
                new JWKSelector(new JWKMatcher.Builder().keyID(KEY_ID).build());

        List<JWK> keys = source.get(selector, null);
        assertEquals(1, keys.size());

        JWK key = keys.getFirst();
        assertEquals(KEY_ID, key.getKeyID());
        assertTrue(key.isPrivate());
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
