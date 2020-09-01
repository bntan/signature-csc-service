package com.bntan.signature.csc.service.web.exceptions;

public class AuthorizationException extends RuntimeException {

    public AuthorizationException(String message) {
        super(message);
    }

    public AuthorizationException(String message, Throwable ex) {
        super(message, ex);
    }
}
