package com.xqtwk.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    MODERATOR_READ("management:read"),
    MODERATOR_UPDATE("management:update"),
    MODERATOR_CREATE("management:create"),
    MODERATOR_DELETE("management:delete")

    ;

    @Getter
    private final String permission;
}
