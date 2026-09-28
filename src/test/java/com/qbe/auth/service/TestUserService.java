package com.qbe.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.qbe.auth.entity.RoleEntity;
import com.qbe.auth.entity.UserEntity;
import com.qbe.auth.enums.Role;
import com.qbe.auth.repository.UserRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class TestUserService {

    private static final String USERNAME = "admin";
    private static final String PASSWORD = "encoded-password";

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Nested
    class LoadUserByUsername {

        @Test
        void shouldLoadUser() {
            UserEntity user = createUser(true, Role.ROLE_ADMIN);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(USERNAME);
            assertThat(result.getPassword()).isEqualTo(PASSWORD);
            assertThat(result.isEnabled()).isTrue();

            verify(userRepository).findByUsername(USERNAME);
        }

        @Test
        void shouldMapRolesToAuthorities() {
            UserEntity user = createUser(true, Role.ROLE_ADMIN, Role.ROLE_USER, Role.ROLE_READER);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result.getAuthorities())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_ADMIN", "ROLE_READER", "ROLE_USER");
        }

        @Test
        void shouldSortAuthoritiesAlphabetically() {
            UserEntity user = createUser(true, Role.ROLE_USER, Role.ROLE_READER, Role.ROLE_ADMIN);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result.getAuthorities())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_ADMIN", "ROLE_READER", "ROLE_USER");
        }

        @Test
        void shouldReturnEnabledUserWhenUserIsEnabled() {
            UserEntity user = createUser(true, Role.ROLE_USER);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result.isEnabled()).isTrue();
        }

        @Test
        void shouldReturnDisabledUserWhenUserIsDisabled() {
            UserEntity user = createUser(false, Role.ROLE_USER);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result.isEnabled()).isFalse();
        }

        @Test
        void shouldLoadUserWithoutRoles() {
            UserEntity user = createUser(true);

            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

            UserDetails result = userService.loadUserByUsername(USERNAME);

            assertThat(result.getAuthorities()).isEmpty();

            assertThat(result.getUsername()).isEqualTo(USERNAME);

            assertThat(result.isEnabled()).isTrue();
        }

        @Test
        void shouldThrowUsernameNotFoundExceptionWhenUserDoesNotExist() {
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.loadUserByUsername(USERNAME))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found: " + USERNAME);

            verify(userRepository).findByUsername(USERNAME);
        }
    }

    private UserEntity createUser(boolean enabled, Role... roles) {

        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername(USERNAME);
        user.setPassword(PASSWORD);
        user.setEnabled(enabled);

        List<RoleEntity> roleEntities =
                List.of(roles).stream().map(this::createRole).toList();

        user.setRoles(new HashSet<>(roleEntities));

        return user;
    }

    private RoleEntity createRole(Role role) {
        RoleEntity roleEntity = new RoleEntity();
        roleEntity.setName(role);

        return roleEntity;
    }
}
