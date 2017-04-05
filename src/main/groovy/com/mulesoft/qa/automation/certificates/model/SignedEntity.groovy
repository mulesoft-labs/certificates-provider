package com.mulesoft.qa.automation.certificates.model

import com.mulesoft.qa.automation.certificates.KeyUtils

import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate

/**
 * Created by naitse on 3/31/17.
 */
class SignedEntity {
    PublicKey signedPublicKey
    PrivateKey signedPrivateKey
    Certificate signedCert

    String getSignedPublicKeyString() {
        return _toString(signedPublicKey)
    }

    String getSignedPrivateKeyString() {
        return _toString(signedPrivateKey)
    }

    String getSignedCertString() {
        return _toString(signedCert)
    }

    private String _toString(def toConvert){
        KeyUtils.certToString(toConvert)
    }
}
