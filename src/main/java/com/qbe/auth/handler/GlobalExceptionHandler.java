package com.qbe.auth.handler;

import com.qbe.auth.exception.InvalidRefreshTokenException;
import com.qbe.auth.exception.UserNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidRefreshTokenException.class)
    ProblemDetail handleInvalidRefreshToken(InvalidRefreshTokenException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());

        problem.setTitle("Invalid refresh token");
        problem.setProperty("error", "invalid_refresh_token");

        return problem;
    }

    @ExceptionHandler(UserNotFoundException.class)
    ProblemDetail handleUserNotFound(UserNotFoundException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());

        problem.setTitle("User not found");
        problem.setProperty("error", "user_not_found");

        return problem;
    }

    @ExceptionHandler(AuthenticationException.class)
    ProblemDetail handleAuthenticationException(AuthenticationException exception) {
        ProblemDetail problem =
                ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid username or password");

        problem.setTitle("Authentication failed");
        problem.setProperty("error", "invalid_credentials");

        return problem;
    }
}
