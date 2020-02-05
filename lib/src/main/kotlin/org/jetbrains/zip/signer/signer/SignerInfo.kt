package org.jetbrains.zip.signer.signer

import java.security.PrivateKey
import java.security.cert.X509Certificate

data class SignerInfo(val certificates: List<X509Certificate>, val privateKey: PrivateKey) {
    init {
        require(certificates.isNotEmpty()) { "Could not find certificates" }
    }
}