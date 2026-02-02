package com.thehook.ias.auth;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;

public class IasSecurityJackson2Module extends SimpleModule {

    public IasSecurityJackson2Module() {
        super(IasSecurityJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        context.setMixInAnnotations(IasUserPrincipal.class, IasUserPrincipalMixin.class);
    }
}
