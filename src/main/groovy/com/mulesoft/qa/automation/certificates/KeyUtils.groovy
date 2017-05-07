package com.mulesoft.qa.automation.certificates

import com.mulesoft.qa.automation.certificates.model.CertificatesBundle
import com.mulesoft.qa.automation.certificates.model.SignedEntity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMWriter

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.Certificate

/**
 * Created by naitse on 3/2/17.
 */
class KeyUtils {

    static {
        Security.addProvider(new BouncyCastleProvider())
    }

    public static KeyPair generateKeyPair(int strength = 2048){
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(strength);
        keyGen.generateKeyPair();
    }

    public static CertificatesBundle generateCertificateBundle(String targetDomain, int signedCertsAmount = 1){
        generateCertificateBundle([ targetDomain ], signedCertsAmount)
    }

    public static CertificatesBundle generateCertificateBundle(List<String> targetDomain = ['defaulting.com'], int signedCertsAmount = 1){

        KeyPair caKeyPair = generateKeyPair()
        KeyPair intKeyPair = generateKeyPair()

        PublicKey caPubKey = caKeyPair.public
        PrivateKey caPrivKey = caKeyPair.private
        Certificate caCert = CAFactory.createMasterCert(caPubKey, caPrivKey);

        PublicKey intPubKey = intKeyPair.public
        PrivateKey intPrivKey = intKeyPair.private
        Certificate intCert = CertFactory.generateSignedCertificate(intPubKey, caPrivKey, caPubKey, 'intermediate');

        CertificatesBundle certificatesBundle = new CertificatesBundle();

        certificatesBundle.CAPublicKey = caPubKey
        certificatesBundle.CAPrivateKey = caPrivKey
        certificatesBundle.CACert = caCert

        certificatesBundle.intermediatePublicKey = intPubKey
        certificatesBundle.intermediatePrivateKey = intPrivKey
        certificatesBundle.intermediateCert = intCert

        certificatesBundle.signedEntities = new ArrayList<SignedEntity>()

        (1..signedCertsAmount).each {
            KeyPair signedKeyPair = generateKeyPair()
            SignedEntity signedEntity = new SignedEntity()
            signedEntity.signedPublicKey = signedKeyPair.public
            signedEntity.signedPrivateKey = signedKeyPair.private
            signedEntity.signedCert = CertFactory.generateSignedCertificate(signedEntity.signedPublicKey, caPrivKey, caPubKey, targetDomain[it -1]);
            certificatesBundle.signedEntities.add(signedEntity)
        }

        certificatesBundle

    }

    public static Map generateCertificateBundleStrings(){
        generateCertificateBundle().toMapStrings()
    }

    public static Map generateCABundle(){
        KeyPair keyPair = generateKeyPair()
        CAFactory.createMasterCert(keyPair.public, keyPair.private)

        [
            privateKey: keyPair.private,
            publicKey: keyPair.public,
            certificate: CAFactory.createMasterCert(keyPair.public, keyPair.private)
        ]
    }

    public static Map generateCABundleStrings(){

        Map caBundle = generateCABundle()

        [
            privateKey: certToString(caBundle.privateKey),
            publicKey: certToString(caBundle.publicKey),
            certificate: certToString(caBundle.certificate)
        ]

    }

    public static Map generateKeyPairStrings(int strength = 2048){

        KeyPair keyPair = generateKeyPair(strength);

        [
            privateKey: certToString(keyPair.getPrivate()),
            publicKey: certToString(keyPair.getPublic())
        ]

    }

    public static Map keyPairToString(KeyPair keyPair){

        [
            privateKey: certToString(keyPair.getPrivate()),
            publicKey: certToString(keyPair.getPublic())
        ]

    }

    public static String certToString(def cert){
        StringWriter sw = new StringWriter();
        PEMWriter w = new PEMWriter(sw)
        w.writeObject(cert);
        w.flush()
        sw.toString()
    }

}
