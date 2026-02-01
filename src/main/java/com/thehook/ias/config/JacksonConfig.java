package com.thehook.ias.config;

import com.fasterxml.jackson.databind.Module;
import com.thehook.ias.auth.IasSecurityJackson2Module;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JacksonConfig {

    @Bean
    public Module iasSecurityJackson2Module() {
        return new IasSecurityJackson2Module();
    }
}
