package com.bntan.signature.csc.service.web.service;

import com.bntan.signature.csc.gen.api.AuthApi;
import com.bntan.signature.csc.gen.api.CredentialsApi;
import com.bntan.signature.csc.gen.api.SignaturesApi;
import com.bntan.signature.csc.gen.handler.ApiClient;
import com.bntan.signature.csc.gen.handler.ApiException;
import com.bntan.signature.csc.gen.handler.auth.Authentication;
import com.bntan.signature.csc.gen.handler.auth.HttpBearerAuth;
import com.bntan.signature.csc.gen.model.*;
import com.bntan.signature.csc.service.web.configuration.SignatureServerConfig;
import com.bntan.signature.csc.service.web.exceptions.SignatureException;
import com.bntan.signature.csc.service.web.utils.ExternalSignatureCMSSignedDataGenerator;
import com.bntan.signature.csc.service.web.utils.ExternalSignatureSignerInfoGenerator;
import com.bntan.signature.csc.service.web.utils.RSASigner;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.Key;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static javax.crypto.Cipher.getInstance;

public class SignatureService implements SignatureInterface {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureService.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SignatureServerConfig config;
    private String accessToken;

    private String userName;
    private String userSecret;
    private String userPassword;

    public SignatureService(SignatureServerConfig config, String accessToken, String userName, String userSecret, String userPassword) {
        this.config = config;
        this.accessToken = accessToken;
        this.userName = userName;
        this.userSecret = userSecret;
        this.userPassword = userPassword;
    }

    public byte[] sign(byte[] in) throws IOException {
        byte[] out;
        try (PDDocument doc1 = PDDocument.load(in); ByteArrayOutputStream baos1 = new ByteArrayOutputStream()) {
            sign(doc1, baos1);
            try (PDDocument doc2 = PDDocument.load(baos1.toByteArray()); ByteArrayOutputStream baos2 = new ByteArrayOutputStream()) {
                doc2.saveIncremental(baos2);
                out = baos2.toByteArray();
            }
        }
        return out;
    }

    private void sign(PDDocument document, OutputStream output) throws IOException {
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setSignDate(Calendar.getInstance());
        document.addSignature(signature, this);
        document.saveIncremental(output);
    }

    @Override
    public byte[] sign(InputStream content) throws SignatureException {
        if ("LOCAL".equals(config.getType())) {
            return signLocal(content);
        } else {
            return signRemote(content);
        }
    }

    public byte[] signRemote(InputStream content) throws SignatureException {
        try {
            ApiClient client = new ApiClient();
            client.setBasePath(config.getURL());
            client.setVerifyingSsl(false);

            if ("REMOTE_BASIC".equals(config.getType())) {
                client.setUsername(userName);
                client.setPassword(userSecret);
                AuthApi AuthApi = new AuthApi(client);
                OutputAuthLogin authLogin = AuthApi.authLogin(new InputAuthLogin());
                if (authLogin == null) {
                    throw new SignatureException("Error when calling signature server. No access_token returned");
                }
                accessToken = authLogin.getAccessToken();
            }

            for (Authentication authn : client.getAuthentications().values()) {
                if (authn instanceof HttpBearerAuth) {
                    ((HttpBearerAuth) authn).setBearerToken(accessToken);
                    break;
                }
            }
            CredentialsApi credentialsApi = new CredentialsApi(client);
            OutputCredentialsList credentialsList = credentialsApi.credentialsList(new InputCredentialsList());
            if (credentialsList == null || credentialsList.getCredentialIDs() == null || credentialsList.getCredentialIDs().isEmpty()) {
                throw new SignatureException("Error when calling signature server. No credential returned");
            }
            String credentialID = credentialsList.getCredentialIDs().get(0);
            OutputCredentialsInfo credentialsInfo = credentialsApi.credentialsInfo(new InputCredentialsInfo().authInfo(true).certInfo(true).credentialID(credentialID));
            if (credentialsInfo == null || credentialsInfo.getCert() == null || credentialsInfo.getCert().getCertificates() == null || credentialsInfo.getCert().getCertificates().isEmpty()) {
                throw new SignatureException("Error when calling signature server. No cert returned");
            }
            String certB64 = credentialsInfo.getCert().getCertificates().get(0);

            ExternalSignatureCMSSignedDataGenerator cmsGenerator = new ExternalSignatureCMSSignedDataGenerator();
            ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(CMSSignedDataGenerator.DIGEST_SHA256, CMSSignedDataGenerator.ENCRYPTION_RSA);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certB64)));
            signerGenerator.setCertificate(cert);
            CMSProcessable input = new CMSProcessableInputStream(content);
            byte[] bytesToSign = signerGenerator.getBytesToSign(PKCSObjectIdentifiers.data, input, "BC");

            OutputCredentialsAuthorize credentialsAuthorize = credentialsApi.credentialsAuthorize(new InputCredentialsAuthorize().credentialID(credentialID).numSignatures(1).PIN(userPassword));
            if (credentialsAuthorize == null || credentialsAuthorize.getSAD() == null) {
                throw new SignatureException("Error when calling signature server. No SAD returned");
            }

            RSASigner signer = new RSASigner(new SHA256Digest());
            signer.init(true);
            signer.update(bytesToSign, 0, bytesToSign.length);
            byte[] hash = signer.getHashToSign();
            String hashStr = Base64.getEncoder().encodeToString(hash);

            SignaturesApi signaturesApi = new SignaturesApi(client);
            OutputSignaturesSignhash signaturesSignHash = signaturesApi.signaturesSignHash(new InputSignaturesSignhash().SAD(credentialsAuthorize.getSAD()).credentialID(credentialID).hash(Arrays.asList(hashStr)).hashAlgo(config.getHashAlgo()).signAlgo(config.getSignAlgo()));
            if (signaturesSignHash == null || signaturesSignHash.getSignatures() == null || signaturesSignHash.getSignatures().isEmpty()) {
                throw new SignatureException("Error when calling signature server. No signature returned");
            }

            String signatureB64 = signaturesSignHash.getSignatures().get(0);
            byte[] signedBytes = Base64.getDecoder().decode(signatureB64);

            signerGenerator.setCertificate(cert);
            signerGenerator.setSignedBytes(signedBytes);
            cmsGenerator.addSignerInf(signerGenerator);
            List<X509Certificate> certList = Arrays.asList(cert);
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            cmsGenerator.addCertificatesAndCRLs(store);
            CMSSignedData signedData = cmsGenerator.generate(input, false);
            return signedData.getEncoded();
        } catch (ApiException ex) {
            throw new SignatureException("Error when calling signature server. Message: " + ex.getMessage() + ". Body: " + ex.getResponseBody(), ex);
        } catch (Exception ex) {
            throw new SignatureException("Error when calling signature server: " + ex.getMessage(), ex);
        }
    }

    public byte[] signLocal(InputStream content) throws SignatureException {
        try {
            File ksFile = new File(config.getKey());
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new FileInputStream(ksFile), config.getPassword().toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            String alias = config.getAlias();
            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, config.getPassword().toCharArray());
            Certificate[] certs = keystore.getCertificateChain(alias);
            X509Certificate cert = (X509Certificate) certs[0];

            ExternalSignatureCMSSignedDataGenerator cmsGenerator = new ExternalSignatureCMSSignedDataGenerator();
            ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(CMSSignedDataGenerator.DIGEST_SHA256, CMSSignedDataGenerator.ENCRYPTION_RSA);
            signerGenerator.setCertificate(cert);
            CMSProcessable input = new CMSProcessableInputStream(content);
            byte[] bytesToSign = signerGenerator.getBytesToSign(PKCSObjectIdentifiers.data, input, "BC");

            /*
            // Signature : Hash and Encrypt with SUN
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(bytesToSign);
            byte[] signedBytes = signature.sign();
           */

            /*
            // Signature : Hash and Encrypt with BouncyCastle
            RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
            AsymmetricKeyParameter key = PrivateKeyFactory.createKey(privateKey.getEncoded());
            signer.init(true, key);
            signer.update(bytesToSign, 0, bytesToSign.length);
            byte[] signedBytes = signer.generateSignature();
            */

            RSASigner signer = new RSASigner(new SHA256Digest());
            signer.init(true);
            signer.update(bytesToSign, 0, bytesToSign.length);
            byte[] hash = signer.getHashToSign();
            byte[] signedBytes = computeRSA(hash, privateKey);

            signerGenerator.setCertificate(cert);
            signerGenerator.setSignedBytes(signedBytes);
            cmsGenerator.addSignerInf(signerGenerator);
            List<X509Certificate> certList = Arrays.asList(cert);
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            cmsGenerator.addCertificatesAndCRLs(store);
            CMSSignedData signedData = cmsGenerator.generate(input, false);
            return signedData.getEncoded();
        } catch (Exception ex) {
            throw new SignatureException("Error when signing locally: " + ex.getMessage(), ex);
        }
    }

    private byte[] computeRSA(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher cipher = getInstance("RSA");
        cipher.init(ENCRYPT_MODE, key);
        byte[] result = cipher.doFinal(data);
        return result;
    }

    private class CMSProcessableInputStream implements CMSProcessable {

        private InputStream in;

        public CMSProcessableInputStream(InputStream is) {
            in = is;
        }

        @Override
        public Object getContent() {
            return null;
        }

        @Override
        public void write(OutputStream out) throws IOException, CMSException {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
        }
    }
}
