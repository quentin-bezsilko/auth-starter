package com.qbe.auth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.qbe.auth.properties.KeyProperties;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

@ExtendWith(MockitoExtension.class)
class TestKeyConfig {

    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";

    private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";

    private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

    @Mock
    private KeyProperties keyProperties;

    private KeyConfig keyConfig;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);

        keyPair = keyPairGenerator.generateKeyPair();

        keyConfig = new KeyConfig(keyProperties);
    }

    @Nested
    class PublicKey {

        @Test
        void shouldLoadPublicKey() {
            String pem =
                    toPem(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, keyPair.getPublic().getEncoded());

            when(keyProperties.publicKey()).thenReturn(resource(pem));

            RSAPublicKey result = keyConfig.publicKey();

            assertThat(result).isNotNull();

            assertThat(result.getAlgorithm()).isEqualTo("RSA");

            assertThat(result.getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
        }

        @Test
        void shouldSupportPemWithLineBreaks() {
            String base64 =
                    Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            String formattedBase64 = base64.replaceAll("(.{64})", "$1\n");

            String pem = PUBLIC_KEY_BEGIN + "\n" + formattedBase64 + "\n" + PUBLIC_KEY_END;

            when(keyProperties.publicKey()).thenReturn(resource(pem));

            RSAPublicKey result = keyConfig.publicKey();

            assertThat(result.getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
        }

        @Test
        void shouldThrowExceptionWhenPublicKeyHasInvalidPemFormat() {
            String pem = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            when(keyProperties.publicKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::publicKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA public key")
                    .hasCauseInstanceOf(IllegalArgumentException.class)
                    .rootCause()
                    .hasMessage("Invalid PEM format");
        }

        @Test
        void shouldThrowExceptionWhenPublicKeyContainsInvalidBase64() {
            String pem =
                    """
                    -----BEGIN PUBLIC KEY-----
                    !!!INVALID-BASE64!!!
                    -----END PUBLIC KEY-----
                    """;

            when(keyProperties.publicKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::publicKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA public key")
                    .hasCauseInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void shouldThrowExceptionWhenPublicKeyIsNotValidX509Key() {
            String pem =
                    toPem(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, "not-an-rsa-public-key".getBytes(StandardCharsets.UTF_8));

            when(keyProperties.publicKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::publicKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA public key");
        }
    }

    @Nested
    class PrivateKey {

        @Test
        void shouldLoadPrivateKey() {
            String pem = toPem(
                    PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, keyPair.getPrivate().getEncoded());

            when(keyProperties.privateKey()).thenReturn(resource(pem));

            RSAPrivateKey result = keyConfig.privateKey();

            assertThat(result).isNotNull();

            assertThat(result.getAlgorithm()).isEqualTo("RSA");

            assertThat(result.getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
        }

        @Test
        void shouldThrowExceptionWhenPrivateKeyHasInvalidPemFormat() {
            String pem = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            when(keyProperties.privateKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::privateKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA private key")
                    .hasCauseInstanceOf(IllegalArgumentException.class)
                    .rootCause()
                    .hasMessage("Invalid PEM format");
        }

        @Test
        void shouldRejectPkcs1PrivateKeyHeader() {
            String encoded =
                    Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            String pem =
                    """
                    -----BEGIN RSA PRIVATE KEY-----
                    %s
                    -----END RSA PRIVATE KEY-----
                    """
                            .formatted(encoded);

            when(keyProperties.privateKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::privateKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA private key")
                    .hasCauseInstanceOf(IllegalArgumentException.class)
                    .rootCause()
                    .hasMessage("Invalid PEM format");
        }

        @Test
        void shouldThrowExceptionWhenPrivateKeyContainsInvalidBase64() {
            String pem =
                    """
                    -----BEGIN PRIVATE KEY-----
                    !!!INVALID-BASE64!!!
                    -----END PRIVATE KEY-----
                    """;

            when(keyProperties.privateKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::privateKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA private key")
                    .hasCauseInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void shouldThrowExceptionWhenPrivateKeyIsNotValidPkcs8Key() {
            String pem = toPem(
                    PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, "not-an-rsa-private-key".getBytes(StandardCharsets.UTF_8));

            when(keyProperties.privateKey()).thenReturn(resource(pem));

            assertThatThrownBy(keyConfig::privateKey)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unable to load RSA private key");
        }
    }

    private Resource resource(String content) {
        return new ByteArrayResource(content.getBytes(StandardCharsets.UTF_8));
    }

    private String toPem(String begin, String end, byte[] encodedKey) {

        String base64 =
                Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(encodedKey);

        return begin + "\n" + base64 + "\n" + end;
    }
}
