package com.mulesoft.qa.automation.certificates.model

import com.mulesoft.qa.automation.certificates.KeyUtils

import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate;

/**
 * Created by naitse on 3/2/17.
 */
class CertificatesBundle {
    PublicKey CAPublicKey
    PrivateKey CAPrivateKey
    Certificate CACert

    PublicKey intermediatePublicKey
    PrivateKey intermediatePrivateKey
    Certificate intermediateCert

    List<SignedEntity> signedEntities

    String getCAPublicKeyString() {
        return _toString(CAPublicKey)
    }

    String getCAPrivateKeyString() {
        return _toString(CAPrivateKey)
    }

    String getCACertString() {
        return _toString(CACert)
    }

    String getIntermediatePublicKeyString() {
        return _toString(intermediatePublicKey)
    }

    String getIntermediatePrivateKeyString() {
        return _toString(intermediatePrivateKey)
    }

    String getIntermediateCertString() {
        return _toString(intermediateCert)
    }

    private String _toString(def toConvert){
        KeyUtils.certToString(toConvert)
    }
}
