package com.mulesoft.qa.automation.certificates

import org.bouncycastle.jce.X509Principal
import org.bouncycastle.x509.X509V1CertificateGenerator

import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/**
 * Created by naitse on 3/2/17.
 */
class CAFactory {

    static X509V1CertificateGenerator v1CertGen = new X509V1CertificateGenerator();

    public static Certificate createMasterCert(PublicKey pubKey, PrivateKey privKey) throws Exception {

        String issuer = "C=AU, O=ARM Automation, OU=ARM Automation";
        String subject = "C=AU, O=ARM Automation, OU=ARM Automation";

        //
        // create the certificate - version 1
        //

        v1CertGen.setSerialNumber(BigInteger.valueOf(1));
        v1CertGen.setIssuerDN(new X509Principal(issuer));
        v1CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
        v1CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
        v1CertGen.setSubjectDN(new X509Principal(subject));
        v1CertGen.setPublicKey(pubKey);
        v1CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        X509Certificate cert = v1CertGen.generate(privKey);

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        return cert;
    }

}
