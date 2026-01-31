package com.thehook.ias.auth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.UUID;

@Getter
public class IasUserPrincipal implements UserDetails {

    private final UUID id;
    private final String email;
    private final String password;
    private final String displayName;
    private final boolean enabled;
    private final boolean emailVerified;
    private final boolean platformOwner;
    private final Collection<? extends GrantedAuthority> authorities;

    public IasUserPrincipal(UUID id, String email, String password, String displayName,
                            boolean enabled, boolean emailVerified, boolean platformOwner,
                            Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.displayName = displayName;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
        this.platformOwner = platformOwner;
        this.authorities = authorities;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return enabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
