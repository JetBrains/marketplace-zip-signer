package org.jetbrains.zip.signer

import org.jetbrains.zip.signer.algorithm.SignatureAlgorithm
import java.security.PrivateKey
import java.security.cert.X509Certificate

class SignerConfig(
    val certificates: List<X509Certificate>,
    val privateKey: PrivateKey,
    val algorithms: List<SignatureAlgorithm>
)