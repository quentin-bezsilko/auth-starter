package com.qbe.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.qbe.auth.entity.RefreshTokenEntity;
import com.qbe.auth.entity.UserEntity;
import com.qbe.auth.exception.InvalidRefreshTokenException;
import com.qbe.auth.properties.JwtProperties;
import com.qbe.auth.repository.RefreshTokenRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TestRefreshTokenService {

    private static final String RAW_TOKEN = "test-refresh-token";

    private static final String ISSUER = "http://localhost:8081/authstarter";

    private static final String AUDIENCE = "springstarter-api";

    private static final Duration ACCESS_TOKEN_DURATION = Duration.ofHours(1);

    private static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(30);

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties =
                new JwtProperties(ISSUER, AUDIENCE, ACCESS_TOKEN_DURATION, REFRESH_TOKEN_DURATION);

        refreshTokenService = new RefreshTokenService(refreshTokenRepository, jwtProperties);
    }

    @Nested
    class Create {

        @Test
        void shouldCreateRefreshToken() {
            UserEntity user = createUser();

            OffsetDateTime before = OffsetDateTime.now();

            String rawToken = refreshTokenService.create(user);

            OffsetDateTime after = OffsetDateTime.now();

            assertThat(rawToken).isNotBlank();

            ArgumentCaptor<RefreshTokenEntity> captor = ArgumentCaptor.forClass(RefreshTokenEntity.class);

            verify(refreshTokenRepository).save(captor.capture());

            RefreshTokenEntity savedToken = captor.getValue();

            assertThat(savedToken.getUser()).isSameAs(user);

            assertThat(savedToken.getTokenHash()).isEqualTo(hash(rawToken));

            assertThat(savedToken.getTokenHash()).hasSize(64);

            assertThat(savedToken.getExpiresAt())
                    .isBetween(before.plus(REFRESH_TOKEN_DURATION), after.plus(REFRESH_TOKEN_DURATION));

            assertThat(savedToken.getUsedAt()).isNull();

            assertThat(savedToken.getRevokedAt()).isNull();
        }

        @Test
        void shouldGenerateUrlSafeBase64TokenContaining32Bytes() {
            UserEntity user = createUser();

            String rawToken = refreshTokenService.create(user);

            byte[] decoded = Base64.getUrlDecoder().decode(rawToken);

            assertThat(decoded).hasSize(32);
        }

        @Test
        void shouldGenerateDifferentTokens() {
            UserEntity user = createUser();

            String firstToken = refreshTokenService.create(user);
            String secondToken = refreshTokenService.create(user);

            assertThat(firstToken).isNotEqualTo(secondToken);

            verify(refreshTokenRepository, times(2)).save(any(RefreshTokenEntity.class));
        }

        @Test
        void shouldPersistHashInsteadOfRawToken() {
            UserEntity user = createUser();

            String rawToken = refreshTokenService.create(user);

            ArgumentCaptor<RefreshTokenEntity> captor = ArgumentCaptor.forClass(RefreshTokenEntity.class);

            verify(refreshTokenRepository).save(captor.capture());

            RefreshTokenEntity savedToken = captor.getValue();

            assertThat(savedToken.getTokenHash()).isNotEqualTo(rawToken);

            assertThat(savedToken.getTokenHash()).isEqualTo(hash(rawToken));
        }
    }

    @Nested
    class Validate {

        @Test
        void shouldReturnRefreshTokenWhenValid() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            RefreshTokenEntity result = refreshTokenService.validate(RAW_TOKEN);

            assertThat(result).isSameAs(refreshToken);

            verify(refreshTokenRepository).findByTokenHash(hash(RAW_TOKEN));
        }

        @Test
        void shouldRejectUnknownRefreshToken() {
            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Invalid refresh token");
        }

        @Test
        void shouldRejectRevokedRefreshToken() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setRevokedAt(OffsetDateTime.now().minusMinutes(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has been revoked");
        }

        @Test
        void shouldRejectAlreadyUsedRefreshToken() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setUsedAt(OffsetDateTime.now().minusMinutes(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has already been used");
        }

        @Test
        void shouldRejectExpiredRefreshToken() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setExpiresAt(OffsetDateTime.now().minusSeconds(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has expired");
        }

        @Test
        void shouldPrioritizeRevokedStateOverUsedState() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setRevokedAt(OffsetDateTime.now().minusMinutes(1));

            refreshToken.setUsedAt(OffsetDateTime.now().minusMinutes(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has been revoked");
        }

        @Test
        void shouldPrioritizeUsedStateOverExpiredState() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setUsedAt(OffsetDateTime.now().minusMinutes(1));

            refreshToken.setExpiresAt(OffsetDateTime.now().minusMinutes(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            assertThatThrownBy(() -> refreshTokenService.validate(RAW_TOKEN))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has already been used");
        }
    }

    @Nested
    class MarkAsUsed {

        @Test
        void shouldMarkRefreshTokenAsUsed() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            OffsetDateTime before = OffsetDateTime.now();

            refreshTokenService.markAsUsed(refreshToken);

            OffsetDateTime after = OffsetDateTime.now();

            assertThat(refreshToken.getUsedAt()).isNotNull().isBetween(before, after);

            verify(refreshTokenRepository).save(refreshToken);
        }
    }

    @Nested
    class Revoke {

        @Test
        void shouldRevokeExistingRefreshToken() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            OffsetDateTime before = OffsetDateTime.now();

            refreshTokenService.revoke(RAW_TOKEN);

            OffsetDateTime after = OffsetDateTime.now();

            assertThat(refreshToken.getRevokedAt()).isNotNull().isBetween(before, after);

            verify(refreshTokenRepository).save(refreshToken);
        }

        @Test
        void shouldDoNothingWhenRefreshTokenDoesNotExist() {
            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.empty());

            refreshTokenService.revoke(RAW_TOKEN);

            verify(refreshTokenRepository).findByTokenHash(hash(RAW_TOKEN));

            verify(refreshTokenRepository, never()).save(any());
        }

        @Test
        void shouldDoNothingWhenRefreshTokenIsAlreadyRevoked() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            OffsetDateTime revokedAt = OffsetDateTime.now().minusMinutes(5);

            refreshToken.setRevokedAt(revokedAt);

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            refreshTokenService.revoke(RAW_TOKEN);

            assertThat(refreshToken.getRevokedAt()).isEqualTo(revokedAt);

            verify(refreshTokenRepository, never()).save(any());
        }

        @Test
        void shouldAllowRevokingAlreadyUsedRefreshToken() {
            RefreshTokenEntity refreshToken = createValidRefreshToken();

            refreshToken.setUsedAt(OffsetDateTime.now().minusMinutes(1));

            when(refreshTokenRepository.findByTokenHash(hash(RAW_TOKEN))).thenReturn(Optional.of(refreshToken));

            refreshTokenService.revoke(RAW_TOKEN);

            assertThat(refreshToken.getRevokedAt()).isNotNull();

            verify(refreshTokenRepository).save(refreshToken);
        }
    }

    @Nested
    class DeleteExpiredTokens {

        @Test
        void shouldDeleteExpiredRefreshTokens() {
            OffsetDateTime before = OffsetDateTime.now();

            refreshTokenService.deleteExpiredTokens();

            OffsetDateTime after = OffsetDateTime.now();

            ArgumentCaptor<OffsetDateTime> captor = ArgumentCaptor.forClass(OffsetDateTime.class);

            verify(refreshTokenRepository).deleteByExpiresAtBefore(captor.capture());

            assertThat(captor.getValue()).isBetween(before, after);
        }
    }

    private UserEntity createUser() {
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername("admin");
        user.setEnabled(true);

        return user;
    }

    private RefreshTokenEntity createValidRefreshToken() {
        RefreshTokenEntity refreshToken = new RefreshTokenEntity();

        refreshToken.setId(1L);
        refreshToken.setUser(createUser());
        refreshToken.setTokenHash(hash(RAW_TOKEN));
        refreshToken.setExpiresAt(OffsetDateTime.now().plusHours(1));

        return refreshToken;
    }

    private String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] value = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(value);

        } catch (Exception exception) {
            throw new AssertionError("Unable to calculate SHA-256 hash in test", exception);
        }
    }
}
