package com.qbe.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.qbe.auth.dto.LoginRequestDto;
import com.qbe.auth.dto.LogoutRequestDto;
import com.qbe.auth.dto.RefreshTokenRequestDto;
import com.qbe.auth.dto.TokenResponseDto;
import com.qbe.auth.service.AuthenticationService;
import java.time.Duration;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
class TestAuthenticationController {

    private static final String USERNAME = "admin";
    private static final String PASSWORD = "password";

    private static final String ACCESS_TOKEN = "access-token";
    private static final String REFRESH_TOKEN = "refresh-token";
    private static final String NEW_ACCESS_TOKEN = "new-access-token";
    private static final String NEW_REFRESH_TOKEN = "new-refresh-token";

    private static final String TOKEN_TYPE = "Bearer";
    private static final long EXPIRES_IN = Duration.ofHours(1).toSeconds();

    @Mock
    private AuthenticationService authenticationService;

    @InjectMocks
    private AuthenticationController authenticationController;

    @Nested
    class Login {

        @Test
        void shouldAuthenticateUserAndReturnTokens() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            TokenResponseDto expectedResponse =
                    new TokenResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE, EXPIRES_IN);

            when(authenticationService.authenticate(request)).thenReturn(expectedResponse);

            ResponseEntity<TokenResponseDto> response = authenticationController.login(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

            assertThat(response.getBody()).isSameAs(expectedResponse);

            assertThat(response.getBody().accessToken()).isEqualTo(ACCESS_TOKEN);

            assertThat(response.getBody().refreshToken()).isEqualTo(REFRESH_TOKEN);

            assertThat(response.getBody().tokenType()).isEqualTo(TOKEN_TYPE);

            assertThat(response.getBody().expiresIn()).isEqualTo(EXPIRES_IN);

            verify(authenticationService).authenticate(request);

            verifyNoMoreInteractions(authenticationService);
        }
    }

    @Nested
    class Refresh {

        @Test
        void shouldRefreshTokenAndReturnNewTokens() {
            RefreshTokenRequestDto request = new RefreshTokenRequestDto(REFRESH_TOKEN);

            TokenResponseDto expectedResponse =
                    new TokenResponseDto(NEW_ACCESS_TOKEN, NEW_REFRESH_TOKEN, TOKEN_TYPE, EXPIRES_IN);

            when(authenticationService.refresh(request)).thenReturn(expectedResponse);

            ResponseEntity<TokenResponseDto> response = authenticationController.refresh(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

            assertThat(response.getBody()).isSameAs(expectedResponse);

            assertThat(response.getBody().accessToken()).isEqualTo(NEW_ACCESS_TOKEN);

            assertThat(response.getBody().refreshToken()).isEqualTo(NEW_REFRESH_TOKEN);

            assertThat(response.getBody().tokenType()).isEqualTo(TOKEN_TYPE);

            assertThat(response.getBody().expiresIn()).isEqualTo(EXPIRES_IN);

            verify(authenticationService).refresh(request);

            verifyNoMoreInteractions(authenticationService);
        }
    }

    @Nested
    class Logout {

        @Test
        void shouldLogoutUserAndReturnNoContent() {
            LogoutRequestDto request = new LogoutRequestDto(REFRESH_TOKEN);

            ResponseEntity<Void> response = authenticationController.logout(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            assertThat(response.getBody()).isNull();
            verify(authenticationService).logout(request);
            verifyNoMoreInteractions(authenticationService);
        }
    }
}
