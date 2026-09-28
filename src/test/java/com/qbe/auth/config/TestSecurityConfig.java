package com.qbe.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbe.auth.service.UserService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@ExtendWith(MockitoExtension.class)
class TestSecurityConfig {

    private static final String KEY_ID = "authstarter-key";

    private SecurityConfig securityConfig;

    @Mock
    private UserService userService;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig();
    }

    @Nested
    class PasswordEncoderBean {

        @Test
        void shouldCreateBCryptPasswordEncoder() {
            PasswordEncoder result = securityConfig.passwordEncoder();

            assertThat(result).isNotNull().isInstanceOf(BCryptPasswordEncoder.class);
        }

        @Test
        void shouldEncodeAndValidatePassword() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            String rawPassword = "password";

            String encodedPassword = passwordEncoder.encode(rawPassword);

            assertThat(encodedPassword).isNotBlank().isNotEqualTo(rawPassword);

            assertThat(passwordEncoder.matches(rawPassword, encodedPassword)).isTrue();
        }

        @Test
        void shouldRejectInvalidPassword() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            String encodedPassword = passwordEncoder.encode("password");

            assertThat(passwordEncoder.matches("wrong-password", encodedPassword))
                    .isFalse();
        }
    }

    @Nested
    class AuthenticationProviderBean {

        @Test
        void shouldCreateDaoAuthenticationProvider() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            DaoAuthenticationProvider result = securityConfig.authenticationProvider(userService, passwordEncoder);

            assertThat(result).isNotNull().isInstanceOf(DaoAuthenticationProvider.class);
        }
    }

    @Nested
    class AuthenticationManagerBean {

        @Test
        void shouldCreateProviderManager() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            DaoAuthenticationProvider provider = securityConfig.authenticationProvider(userService, passwordEncoder);

            AuthenticationManager result = securityConfig.authenticationManager(provider);

            assertThat(result).isNotNull().isInstanceOf(ProviderManager.class);
        }

        @Test
        void shouldConfigureAuthenticationProvider() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            DaoAuthenticationProvider provider = securityConfig.authenticationProvider(userService, passwordEncoder);

            ProviderManager authenticationManager = (ProviderManager) securityConfig.authenticationManager(provider);

            assertThat(authenticationManager.getProviders()).containsExactly(provider);
        }
    }

    @Nested
    class JwkSourceBean {

        @Test
        void shouldCreateJwkSourceContainingRsaKey() throws Exception {
            KeyPair keyPair = generateRsaKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            JWKSource<SecurityContext> jwkSource = securityConfig.jwkSource(publicKey, privateKey);

            JWKSelector selector =
                    new JWKSelector(new JWKMatcher.Builder().keyID(KEY_ID).build());

            List<JWK> keys = jwkSource.get(selector, null);

            assertThat(keys).hasSize(1);

            RSAKey rsaKey = (RSAKey) keys.getFirst();

            assertThat(rsaKey.getKeyID()).isEqualTo(KEY_ID);

            assertThat(rsaKey.toRSAPublicKey().getEncoded()).isEqualTo(publicKey.getEncoded());

            assertThat(rsaKey.toRSAPrivateKey().getEncoded()).isEqualTo(privateKey.getEncoded());
        }
    }

    @Nested
    class JwtEncoderBean {

        @Test
        void shouldCreateNimbusJwtEncoder() throws Exception {

            KeyPair keyPair = generateRsaKeyPair();

            JWKSource<SecurityContext> jwkSource =
                    securityConfig.jwkSource((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

            JwtEncoder result = securityConfig.jwtEncoder(jwkSource);

            assertThat(result).isNotNull().isInstanceOf(NimbusJwtEncoder.class);
        }
    }

    private KeyPair generateRsaKeyPair() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.generateKeyPair();
    }
}
