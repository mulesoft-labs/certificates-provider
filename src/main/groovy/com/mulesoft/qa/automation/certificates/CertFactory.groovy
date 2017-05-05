package com.mulesoft.qa.automation.certificates

import org.bouncycastle.asn1.x509.X509Extensions
import org.bouncycastle.jce.X509Principal
import org.bouncycastle.x509.X509V3CertificateGenerator
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure

import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/**
 * Created by naitse on 3/2/17.
 */
class CertFactory {

    public static Certificate generateSignedCertificate(
            PublicKey pubKey,
            PrivateKey signingPrivateKey,
            PublicKey signingPublicKey,
            String CN) throws Exception {

        static X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

        //
        // signers name table.
        //
        Hashtable sAttrs = new Hashtable();
        Vector sOrder = new Vector();

        sAttrs.put(X509Principal.C, "AU");
        sAttrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        sAttrs.put(X509Principal.OU, "Bouncy Intermediate Certificate");
        sAttrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

        sOrder.addElement(X509Principal.C);
        sOrder.addElement(X509Principal.O);
        sOrder.addElement(X509Principal.OU);
        sOrder.addElement(X509Principal.EmailAddress);

        //
        // subjects name table.
        //
        Hashtable attrs = new Hashtable();
        Vector order = new Vector();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.CN, CN);
        attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

        order.addElement(X509Principal.C);
        order.addElement(X509Principal.O);
        order.addElement(X509Principal.L);
        order.addElement(X509Principal.CN);
        order.addElement(X509Principal.EmailAddress);

        //
        // create the certificate - version 3
        //
        v3CertGen.reset();

        v3CertGen.setSerialNumber(BigInteger.valueOf(3));
        v3CertGen.setIssuerDN(new X509Principal(sOrder, sAttrs));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
        v3CertGen.setSubjectDN(new X509Principal(order, attrs));
        v3CertGen.setPublicKey(pubKey);
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        v3CertGen.addExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifierStructure(pubKey));

        v3CertGen.addExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifierStructure(signingPublicKey));

        X509Certificate cert = v3CertGen.generateX509Certificate(signingPrivateKey);

        cert.checkValidity(new Date());
        cert.verify(signingPublicKey);

        return cert;
    }
}
