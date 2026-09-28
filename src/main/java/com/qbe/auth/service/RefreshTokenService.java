package com.qbe.auth.service;

import com.qbe.auth.entity.RefreshTokenEntity;
import com.qbe.auth.entity.UserEntity;
import com.qbe.auth.exception.InvalidRefreshTokenException;
import com.qbe.auth.properties.JwtProperties;
import com.qbe.auth.repository.RefreshTokenRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int TOKEN_BYTES = 32;
    private static final String HASH_ALGORITHM = "SHA-256";

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;

    /**
     * Creates a new refresh token for a user.
     *
     * <p>The raw token is returned to the client, while only its SHA-256 hash
     * is persisted in the database.
     *
     * @param user the user associated with the refresh token
     * @return the raw refresh token
     */
    @Transactional
    public String create(UserEntity user) {
        String rawToken = generateToken();

        RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hash(rawToken));
        refreshToken.setExpiresAt(OffsetDateTime.now(ZoneOffset.UTC).plus(jwtProperties.refreshTokenDuration()));

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    /**
     * Finds and validates a refresh token.
     *
     * @param rawToken the raw refresh token
     * @return the validated refresh token entity
     * @throws InvalidRefreshTokenException if the token does not exist,
     *         is expired, revoked or has already been used
     */
    @Transactional(readOnly = true)
    public RefreshTokenEntity validate(String rawToken) {
        String tokenHash = hash(rawToken);

        RefreshTokenEntity refreshToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (refreshToken.getRevokedAt() != null) {
            throw new InvalidRefreshTokenException("Refresh token has been revoked");
        }

        if (refreshToken.getUsedAt() != null) {
            throw new InvalidRefreshTokenException("Refresh token has already been used");
        }

        if (refreshToken.getExpiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new InvalidRefreshTokenException("Refresh token has expired");
        }

        return refreshToken;
    }

    /**
     * Marks a refresh token as used.
     *
     * @param refreshToken the refresh token to mark as used
     */
    @Transactional
    public void markAsUsed(RefreshTokenEntity refreshToken) {
        refreshToken.setUsedAt(OffsetDateTime.now(ZoneOffset.UTC));
        refreshTokenRepository.save(refreshToken);
    }

    /**
     * Revokes a refresh token if it exists and has not already been revoked.
     *
     * @param rawToken the raw refresh token to revoke
     */
    @Transactional
    public void revoke(String rawToken) {
        String tokenHash = hash(rawToken);

        refreshTokenRepository
                .findByTokenHash(tokenHash)
                .filter(refreshToken -> refreshToken.getRevokedAt() == null)
                .ifPresent(refreshToken -> {
                    refreshToken.setRevokedAt(OffsetDateTime.now(ZoneOffset.UTC));
                    refreshTokenRepository.save(refreshToken);
                });
    }

    /**
     * Deletes all expired refresh tokens.
     */
    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteByExpiresAtBefore(OffsetDateTime.now(ZoneOffset.UTC));
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " algorithm is not available", e);
        }
    }
}
