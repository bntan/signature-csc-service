package com.bntan.signature.csc.service.web.controller;

import com.bntan.signature.csc.service.gen.api.SignPDFApiController;
import com.bntan.signature.csc.service.gen.model.DocumentSignatureRequest;
import com.bntan.signature.csc.service.gen.model.DocumentSignatureResponse;
import com.bntan.signature.csc.service.web.configuration.SignatureServerConfig;
import com.bntan.signature.csc.service.web.exceptions.AuthorizationException;
import com.bntan.signature.csc.service.web.exceptions.SignatureException;
import com.bntan.signature.csc.service.web.service.AuthorizationService;
import com.bntan.signature.csc.service.web.service.SignatureService;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;

import javax.validation.Valid;
import java.util.Base64;

@Controller
public class SignatureController extends SignPDFApiController {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureController.class);

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private SignatureServerConfig signatureServerConfig;

    @Override
    public ResponseEntity<DocumentSignatureResponse> signPDF(@ApiParam(value = "The signature request", required = true) @Valid @RequestBody DocumentSignatureRequest request) {
        DocumentSignatureResponse response = new DocumentSignatureResponse();
        try {
            LOG.info("Start signPDF");
            String accessToken = null;
            if ("REMOTE_OAUTH".equals(signatureServerConfig.getType())) {
                accessToken = authorizationService.getAccessToken(request.getAuthorizationCode(), request.getClientId(), request.getRedirectUri());
                LOG.debug("The access_token is: " + accessToken);
            }
            SignatureService service = new SignatureService(signatureServerConfig, accessToken, request.getUserName(), request.getUserSecret(), request.getUserPassword());
            byte[] out = service.sign(Base64.getDecoder().decode(request.getDocumentToSign()));
            LOG.info("End signPDF");
            response.setSignedDocument(Base64.getEncoder().encodeToString(out));
            return new ResponseEntity<DocumentSignatureResponse>(response, HttpStatus.OK);
        } catch (AuthorizationException ex) {
            LOG.error("Authorization error when calling signPDF", ex);
            response.setErrorCode("AUTHORIZATION_ERROR");
            response.setErrorMessage(ex.getMessage());
            return new ResponseEntity<DocumentSignatureResponse>(response, HttpStatus.UNAUTHORIZED);
        } catch (SignatureException ex) {
            LOG.error("Signature error when calling signPDF", ex);
            response.setErrorCode("SIGNATURE_ERROR");
            response.setErrorMessage(ex.getMessage());
            return new ResponseEntity<DocumentSignatureResponse>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOG.error("Error when calling signPDF", ex);
            response.setErrorCode("INTERNAL_ERROR");
            response.setErrorMessage(ex.getMessage());
            return new ResponseEntity<DocumentSignatureResponse>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
