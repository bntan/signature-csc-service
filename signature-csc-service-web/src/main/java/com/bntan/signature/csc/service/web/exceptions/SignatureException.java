package com.bntan.signature.csc.service.web.exceptions;

public class SignatureException extends RuntimeException {

    public SignatureException(String message) {
        super(message);
    }

    public SignatureException(String message, Throwable ex) {
        super(message, ex);
    }
}
