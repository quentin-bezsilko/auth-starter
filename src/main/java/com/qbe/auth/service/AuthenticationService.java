package com.qbe.auth.service;

import com.qbe.auth.dto.LoginRequestDto;
import com.qbe.auth.dto.LogoutRequestDto;
import com.qbe.auth.dto.RefreshTokenRequestDto;
import com.qbe.auth.dto.TokenResponseDto;
import com.qbe.auth.entity.PermissionEntity;
import com.qbe.auth.entity.RefreshTokenEntity;
import com.qbe.auth.entity.UserEntity;
import com.qbe.auth.exception.InvalidRefreshTokenException;
import com.qbe.auth.properties.JwtProperties;
import com.qbe.auth.repository.UserRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final String TOKEN_TYPE = "Bearer";

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public TokenResponseDto authenticate(LoginRequestDto request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        UserEntity user = userRepository
                .findByUsername(authentication.getName())
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        String accessToken = createAccessToken(user);
        String refreshToken = refreshTokenService.create(user);

        return new TokenResponseDto(
                accessToken,
                refreshToken,
                TOKEN_TYPE,
                jwtProperties.accessTokenDuration().toSeconds());
    }

    @Transactional
    public TokenResponseDto refresh(RefreshTokenRequestDto request) {
        RefreshTokenEntity currentRefreshToken = refreshTokenService.validate(request.refreshToken());

        UserEntity user = currentRefreshToken.getUser();

        if (!user.isEnabled()) {
            throw new InvalidRefreshTokenException("User is disabled");
        }

        refreshTokenService.markAsUsed(currentRefreshToken);

        String accessToken = createAccessToken(user);
        String newRefreshToken = refreshTokenService.create(user);

        return new TokenResponseDto(
                accessToken,
                newRefreshToken,
                TOKEN_TYPE,
                jwtProperties.accessTokenDuration().toSeconds());
    }

    @Transactional
    public void logout(LogoutRequestDto request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    private String createAccessToken(UserEntity user) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(jwtProperties.accessTokenDuration());

        List<String> authorities = resolveAuthorities(user);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .subject(user.getUsername())
                .audience(List.of(jwtProperties.audience()))
                .id(UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("userId", user.getId())
                .claim("authorities", authorities)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private List<String> resolveAuthorities(UserEntity user) {
        return user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(PermissionEntity::getName)
                .distinct()
                .sorted()
                .toList();
    }
}
