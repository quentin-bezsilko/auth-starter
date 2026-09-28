package com.qbe.auth.config;

import com.qbe.auth.properties.KeyProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class KeyConfig {

    private static final String RSA = "RSA";

    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

    private final KeyProperties keyProperties;

    @Bean
    RSAPublicKey publicKey() {
        try {
            byte[] decoded = decodePem(
                    keyProperties.publicKey().getContentAsString(StandardCharsets.UTF_8),
                    PUBLIC_KEY_BEGIN,
                    PUBLIC_KEY_END);

            return (RSAPublicKey) KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(decoded));

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to load RSA public key", e);
        }
    }

    @Bean
    RSAPrivateKey privateKey() {
        try {
            byte[] decoded = decodePem(
                    keyProperties.privateKey().getContentAsString(StandardCharsets.UTF_8),
                    PRIVATE_KEY_BEGIN,
                    PRIVATE_KEY_END);

            return (RSAPrivateKey) KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(decoded));

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to load RSA private key", e);
        }
    }

    private static byte[] decodePem(String pem, String beginHeader, String endHeader) {
        if (!pem.contains(beginHeader) || !pem.contains(endHeader)) {
            throw new IllegalArgumentException("Invalid PEM format");
        }

        String encoded = pem.replace(beginHeader, "").replace(endHeader, "");
        return Base64.getMimeDecoder().decode(encoded);
    }
}
