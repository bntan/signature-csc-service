package com.bntan.signature.csc.service.web.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorizationServerConfig {

    @Value("${authorization.server.url}")
    private String url;
    @Value("${authorization.server.client.id}")
    private String clientId;
    @Value("${authorization.server.client.secret}")
    private String clientSecret;

    public String getURL() {
        return url;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

}
