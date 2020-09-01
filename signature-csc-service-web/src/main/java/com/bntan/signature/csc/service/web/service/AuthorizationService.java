package com.bntan.signature.csc.service.web.service;

import com.bntan.signature.csc.service.web.configuration.AuthorizationServerConfig;
import com.bntan.signature.csc.service.web.exceptions.AuthorizationException;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.security.sasl.AuthenticationException;

@Service
public class AuthorizationService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

    @Autowired
    private AuthorizationServerConfig config;

    public String getAccessToken(String authorizationCode, String clientId, String redirectURI) throws AuthenticationException {
        if (!config.getClientId().equals(clientId)) {
            throw new AuthorizationException("The client_id (" + clientId + ") is not allowed");
        }
        try {
            TokenResponse response = new AuthorizationCodeTokenRequest(
                    new NetHttpTransport.Builder().doNotValidateCertificate().build(),
                    new JacksonFactory(),
                    new GenericUrl(config.getURL() + "/token"), authorizationCode)
                    .setClientAuthentication(new BasicAuthentication(config.getClientId(), config.getClientSecret()))
                    .setRedirectUri(redirectURI)
                    .setRequestInitializer(
                            new HttpRequestInitializer() {
                                @Override
                                public void initialize(HttpRequest request) {
                                    request.getHeaders().setAccept("application/json");
                                }
                            })
                    .execute();
            return response.getAccessToken();
        } catch (Exception ex) {
            throw new AuthorizationException("Error when calling authorization server: " + ex.getMessage(), ex);
        }
    }
}
