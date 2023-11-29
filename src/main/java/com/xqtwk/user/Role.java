package com.xqtwk.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.xqtwk.user.Permission.*;

@RequiredArgsConstructor
public enum Role {

    USER(Collections.emptySet()), // no permissions
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE,
                    MODERATOR_READ,
                    MODERATOR_UPDATE,
                    MODERATOR_DELETE,
                    MODERATOR_CREATE
            )
    ),
    MODERATOR(
            Set.of(
                    MODERATOR_READ,
                    MODERATOR_UPDATE,
                    MODERATOR_DELETE,
                    MODERATOR_CREATE
            )
    );

    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
