package org.jetbrains.zip.signer

import java.security.PrivateKey
import java.security.cert.X509Certificate

class SignerInfo(
    val certificates: List<X509Certificate>,
    val privateKey: PrivateKey
)