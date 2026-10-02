package com.qbe.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.qbe.auth.dto.*;
import com.qbe.auth.service.AuthenticationService;
import java.time.Duration;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
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
        void shouldAuthenticateUserAndReturnAccessTokenAndRefreshTokenCookie() {
            LoginRequestDto request = new LoginRequestDto(USERNAME, PASSWORD);

            AuthenticationTokensDto tokens =
                    new AuthenticationTokensDto(ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE, EXPIRES_IN);

            when(authenticationService.authenticate(request)).thenReturn(tokens);

            ResponseEntity<TokenResponseDto> response = authenticationController.login(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getBody().tokenType()).isEqualTo(TOKEN_TYPE);
            assertThat(response.getBody().expiresIn()).isEqualTo(EXPIRES_IN);

            String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
            assertThat(setCookie).isNotNull();
            assertThat(setCookie)
                    .contains("refreshToken=" + REFRESH_TOKEN)
                    .contains("HttpOnly")
                    .contains("Path=/")
                    .contains("SameSite=Lax");

            verify(authenticationService).authenticate(request);
            verifyNoMoreInteractions(authenticationService);
        }
    }

    @Nested
    class Refresh {

        @Test
        void shouldRefreshTokenAndReturnNewAccessTokenAndRefreshTokenCookie() {
            AuthenticationTokensDto tokens =
                    new AuthenticationTokensDto(NEW_ACCESS_TOKEN, NEW_REFRESH_TOKEN, TOKEN_TYPE, EXPIRES_IN);

            when(authenticationService.refresh(REFRESH_TOKEN)).thenReturn(tokens);

            ResponseEntity<TokenResponseDto> response = authenticationController.refresh(REFRESH_TOKEN);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

            // Body
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
            assertThat(response.getBody().tokenType()).isEqualTo(TOKEN_TYPE);
            assertThat(response.getBody().expiresIn()).isEqualTo(EXPIRES_IN);

            // Refresh token cookie
            String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);

            assertThat(setCookie).isNotNull();
            assertThat(setCookie)
                    .contains("refreshToken=" + NEW_REFRESH_TOKEN)
                    .contains("HttpOnly")
                    .contains("Path=/")
                    .contains("SameSite=Lax");

            verify(authenticationService).refresh(REFRESH_TOKEN);
            verifyNoMoreInteractions(authenticationService);
        }
    }

    @Nested
    class Logout {

        @Test
        void shouldLogoutUserAndReturnNoContent() {
            ResponseEntity<Void> response = authenticationController.logout(REFRESH_TOKEN);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            assertThat(response.getBody()).isNull();

            verify(authenticationService).logout(REFRESH_TOKEN);
            verifyNoMoreInteractions(authenticationService);
        }
    }
}
