package com.qbe.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.qbe.auth.dto.LoginRequestDto;
import com.qbe.auth.dto.LogoutRequestDto;
import com.qbe.auth.dto.RefreshTokenRequestDto;
import com.qbe.auth.dto.TokenResponseDto;
import com.qbe.auth.entity.PermissionEntity;
import com.qbe.auth.entity.RefreshTokenEntity;
import com.qbe.auth.entity.RoleEntity;
import com.qbe.auth.entity.UserEntity;
import com.qbe.auth.enums.Role;
import com.qbe.auth.exception.InvalidRefreshTokenException;
import com.qbe.auth.properties.JwtProperties;
import com.qbe.auth.repository.UserRepository;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

@ExtendWith(MockitoExtension.class)
class TestAuthenticationService {

    private static final String USERNAME = "admin";
    private static final String PASSWORD = "password";

    private static final String ACCESS_TOKEN = "access-token";
    private static final String REFRESH_TOKEN = "refresh-token";
    private static final String NEW_REFRESH_TOKEN = "new-refresh-token";

    private static final String ISSUER = "http://localhost:8081/authstarter";
    private static final String AUDIENCE = "springstarter-api";

    private static final Duration ACCESS_TOKEN_DURATION = Duration.ofHours(1);
    private static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(30);

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private Authentication authentication;

    @Mock
    private Jwt jwt;

    private AuthenticationService authenticationService;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties =
                new JwtProperties(ISSUER, AUDIENCE, ACCESS_TOKEN_DURATION, REFRESH_TOKEN_DURATION);

        authenticationService = new AuthenticationService(
                authenticationManager, jwtEncoder, jwtProperties, userRepository, refreshTokenService);
    }

    @Nested
    class Authenticate {

        @Test
        void shouldAuthenticateUserAndReturnTokens() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            UserEntity user = createUser();

            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(authentication.getName()).thenReturn(USERNAME);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(REFRESH_TOKEN);

            TokenResponseDto result = authenticationService.authenticate(request);

            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresIn()).isEqualTo(ACCESS_TOKEN_DURATION.toSeconds());

            verify(authenticationManager).authenticate(new UsernamePasswordAuthenticationToken(USERNAME, PASSWORD));

            verify(userRepository).findByUsername(USERNAME);
            verify(refreshTokenService).create(user);
            verify(jwtEncoder).encode(any(JwtEncoderParameters.class));
        }

        @Test
        void shouldThrowExceptionWhenAuthenticatedUserCannotBeFound() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(authentication.getName()).thenReturn(USERNAME);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authenticationService.authenticate(request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Authenticated user not found");

            verify(refreshTokenService, never()).create(any());

            verify(jwtEncoder, never()).encode(any());
        }

        @Test
        void shouldGenerateExpectedJwtClaims() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            UserEntity user = createUser();

            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(authentication.getName()).thenReturn(USERNAME);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(REFRESH_TOKEN);

            authenticationService.authenticate(request);

            ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);

            verify(jwtEncoder).encode(captor.capture());

            JwtClaimsSet claims = captor.getValue().getClaims();

            assertThat(claims.getIssuer()).hasToString(ISSUER);

            assertThat(claims.getSubject()).isEqualTo(USERNAME);

            assertThat(claims.getAudience()).containsExactly(AUDIENCE);

            assertThat(Collections.singletonList(claims.getClaim("userId"))).isEqualTo(List.of(user.getId()));

            assertThat(claims.getClaimAsStringList("authorities")).containsExactly("READ", "WRITE");

            assertThat(claims.getId()).isNotBlank();

            assertThat(claims.getIssuedAt()).isNotNull();

            assertThat(claims.getExpiresAt()).isNotNull();

            assertThat(claims.getExpiresAt()).isEqualTo(claims.getIssuedAt().plus(ACCESS_TOKEN_DURATION));
        }

        @Test
        void shouldGenerateValidUuidAsJwtId() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            UserEntity user = createUser();

            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(authentication.getName()).thenReturn(USERNAME);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(REFRESH_TOKEN);

            authenticationService.authenticate(request);

            ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);

            verify(jwtEncoder).encode(captor.capture());

            String jwtId = captor.getValue().getClaims().getId();

            assertThat(jwtId).isNotNull();

            assertThatCodeIsValidUuid(jwtId);
        }

        @Test
        void shouldRemoveDuplicateAuthoritiesAndSortThem() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            UserEntity user = createUserWithDuplicatePermissions();

            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(authentication.getName()).thenReturn(USERNAME);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(REFRESH_TOKEN);

            authenticationService.authenticate(request);

            ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);

            verify(jwtEncoder).encode(captor.capture());

            List<String> authorities = captor.getValue().getClaims().getClaimAsStringList("authorities");

            assertThat(authorities).containsExactly("READ", "WRITE");
        }
    }

    @Nested
    class Refresh {

        @Test
        void shouldRefreshTokens() {
            RefreshTokenRequestDto request = new RefreshTokenRequestDto(REFRESH_TOKEN);

            UserEntity user = createUser();

            RefreshTokenEntity currentRefreshToken = new RefreshTokenEntity();

            currentRefreshToken.setUser(user);

            when(refreshTokenService.validate(REFRESH_TOKEN)).thenReturn(currentRefreshToken);

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(NEW_REFRESH_TOKEN);

            TokenResponseDto result = authenticationService.refresh(request);

            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(result.refreshToken()).isEqualTo(NEW_REFRESH_TOKEN);
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresIn()).isEqualTo(ACCESS_TOKEN_DURATION.toSeconds());

            verify(refreshTokenService).validate(REFRESH_TOKEN);

            verify(refreshTokenService).markAsUsed(currentRefreshToken);

            verify(refreshTokenService).create(user);
        }

        @Test
        void shouldRejectRefreshWhenUserIsDisabled() {
            RefreshTokenRequestDto request = new RefreshTokenRequestDto(REFRESH_TOKEN);

            UserEntity user = createUser();
            user.setEnabled(false);

            RefreshTokenEntity refreshToken = new RefreshTokenEntity();

            refreshToken.setUser(user);

            when(refreshTokenService.validate(REFRESH_TOKEN)).thenReturn(refreshToken);

            assertThatThrownBy(() -> authenticationService.refresh(request))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("User is disabled");

            verify(refreshTokenService).validate(REFRESH_TOKEN);

            verify(refreshTokenService, never()).markAsUsed(any());

            verify(refreshTokenService, never()).create(any());

            verify(jwtEncoder, never()).encode(any());
        }

        @Test
        void shouldPropagateInvalidRefreshTokenException() {
            RefreshTokenRequestDto request = new RefreshTokenRequestDto(REFRESH_TOKEN);

            when(refreshTokenService.validate(REFRESH_TOKEN))
                    .thenThrow(new InvalidRefreshTokenException("Refresh token has expired"));

            assertThatThrownBy(() -> authenticationService.refresh(request))
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Refresh token has expired");

            verify(refreshTokenService, never()).markAsUsed(any());

            verify(refreshTokenService, never()).create(any());

            verify(jwtEncoder, never()).encode(any());
        }

        @Test
        void shouldGenerateJwtWithUserAuthoritiesDuringRefresh() {
            RefreshTokenRequestDto request = new RefreshTokenRequestDto(REFRESH_TOKEN);

            UserEntity user = createUserWithDuplicatePermissions();

            RefreshTokenEntity refreshToken = new RefreshTokenEntity();

            refreshToken.setUser(user);

            when(refreshTokenService.validate(REFRESH_TOKEN)).thenReturn(refreshToken);

            when(jwtEncoder.encode(any())).thenReturn(jwt);

            when(jwt.getTokenValue()).thenReturn(ACCESS_TOKEN);

            when(refreshTokenService.create(user)).thenReturn(NEW_REFRESH_TOKEN);

            authenticationService.refresh(request);

            ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);

            verify(jwtEncoder).encode(captor.capture());

            JwtClaimsSet claims = captor.getValue().getClaims();

            assertThat(claims.getSubject()).isEqualTo(USERNAME);

            assertThat(claims.getClaimAsStringList("authorities")).containsExactly("READ", "WRITE");
        }
    }

    @Nested
    class Logout {

        @Test
        void shouldRevokeRefreshToken() {
            LogoutRequestDto request = new LogoutRequestDto(REFRESH_TOKEN);

            authenticationService.logout(request);

            verify(refreshTokenService).revoke(REFRESH_TOKEN);
        }
    }

    private UserEntity createUser() {
        PermissionEntity read = createPermission("READ");
        PermissionEntity write = createPermission("WRITE");

        RoleEntity role = new RoleEntity();
        role.setName(Role.ROLE_ADMIN);
        role.setPermissions(new HashSet<>(List.of(read, write)));

        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername(USERNAME);
        user.setPassword("encoded-password");
        user.setEnabled(true);
        user.setRoles(new HashSet<>(List.of(role)));

        return user;
    }

    private UserEntity createUserWithDuplicatePermissions() {
        PermissionEntity readFromAdmin = createPermission("READ");

        PermissionEntity write = createPermission("WRITE");

        PermissionEntity readFromReader = createPermission("READ");

        RoleEntity adminRole = new RoleEntity();
        adminRole.setName(Role.ROLE_ADMIN);
        adminRole.setPermissions(new HashSet<>(List.of(readFromAdmin, write)));

        RoleEntity readerRole = new RoleEntity();
        readerRole.setName(Role.ROLE_READER);
        readerRole.setPermissions(new HashSet<>(List.of(readFromReader)));

        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername(USERNAME);
        user.setPassword("encoded-password");
        user.setEnabled(true);
        user.setRoles(new HashSet<>(List.of(adminRole, readerRole)));

        return user;
    }

    private PermissionEntity createPermission(String name) {
        PermissionEntity permission = new PermissionEntity();

        permission.setName(name);

        return permission;
    }

    private void assertThatCodeIsValidUuid(String value) {
        assertThat(UUID.fromString(value)).hasToString(value);
    }
}
