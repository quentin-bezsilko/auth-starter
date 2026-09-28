package com.qbe.auth.repository;

import com.qbe.auth.entity.RoleEntity;
import com.qbe.auth.enums.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    Optional<RoleEntity> findByName(Role name);
}
