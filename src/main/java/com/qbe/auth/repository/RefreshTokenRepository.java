package com.qbe.auth.repository;

import com.qbe.auth.entity.RefreshTokenEntity;
import java.time.OffsetDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    void deleteByExpiresAtBefore(OffsetDateTime expirationDate);

    void deleteByUserId(Long userId);
}
