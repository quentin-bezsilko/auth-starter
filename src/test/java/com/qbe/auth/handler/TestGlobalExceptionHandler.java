package com.qbe.auth.handler;

import static org.assertj.core.api.Assertions.assertThat;

import com.qbe.auth.exception.InvalidRefreshTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

class TestGlobalExceptionHandler {

    private GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
    }

    @Nested
    class HandleInvalidRefreshToken {

        @Test
        void shouldReturnUnauthorizedProblemDetail() {
            InvalidRefreshTokenException exception = new InvalidRefreshTokenException("Invalid refresh token");

            ProblemDetail result = globalExceptionHandler.handleInvalidRefreshToken(exception);

            assertThat(result).isNotNull();

            assertThat(result.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        }

        @Test
        void shouldReturnInvalidRefreshTokenProblemDetail() {
            InvalidRefreshTokenException exception = new InvalidRefreshTokenException("Refresh token has expired");

            ProblemDetail result = globalExceptionHandler.handleInvalidRefreshToken(exception);

            assertThat(result.getTitle()).isEqualTo("Invalid refresh token");

            assertThat(result.getDetail()).isEqualTo("Refresh token has expired");

            assertThat(result.getProperties()).containsEntry("error", "invalid_refresh_token");
        }

        @Test
        void shouldUseExceptionMessageAsProblemDetail() {
            InvalidRefreshTokenException exception =
                    new InvalidRefreshTokenException("Refresh token has already been used");

            ProblemDetail result = globalExceptionHandler.handleInvalidRefreshToken(exception);

            assertThat(result.getDetail()).isEqualTo("Refresh token has already been used");
        }
    }
}
