package com.qbe.auth.controller;

import com.qbe.auth.dto.LoginRequestDto;
import com.qbe.auth.dto.LogoutRequestDto;
import com.qbe.auth.dto.RefreshTokenRequestDto;
import com.qbe.auth.dto.TokenResponseDto;
import com.qbe.auth.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication, token refresh and logout operations")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Operation(
            summary = "Authenticate a user",
            description =
                    "Authenticates a user using username and password " + "and returns access and refresh tokens.")
    @ApiResponse(responseCode = "200", description = "Authentication successful")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid username or password")
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {

        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @Operation(
            summary = "Refresh an access token",
            description = "Generates a new access token using a valid refresh token.")
    @ApiResponse(responseCode = "200", description = "Token refreshed successfully")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token")
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(@Valid @RequestBody RefreshTokenRequestDto request) {

        return ResponseEntity.ok(authenticationService.refresh(request));
    }

    @Operation(summary = "Logout a user", description = "Revokes the provided refresh token.")
    @ApiResponse(responseCode = "204", description = "Logout successful")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid refresh token")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequestDto request) {

        authenticationService.logout(request);

        return ResponseEntity.noContent().build();
    }
}
