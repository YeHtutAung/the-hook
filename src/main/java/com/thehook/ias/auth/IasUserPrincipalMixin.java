package com.thehook.ias.auth;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class IasUserPrincipalMixin {

    @JsonCreator
    IasUserPrincipalMixin(
            @JsonProperty("id") UUID id,
            @JsonProperty("email") String email,
            @JsonProperty("password") String password,
            @JsonProperty("displayName") String displayName,
            @JsonProperty("enabled") boolean enabled,
            @JsonProperty("emailVerified") boolean emailVerified,
            @JsonProperty("platformOwner") boolean platformOwner,
            @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
    }
}
