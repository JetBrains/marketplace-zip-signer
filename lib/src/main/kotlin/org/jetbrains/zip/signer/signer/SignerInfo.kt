package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.DSAKey
import java.security.interfaces.RSAKey

class SignerInfo(
    val certificates: List<X509Certificate>,
    val privateKey: PrivateKey
) {

    init {
        require(certificates.isNotEmpty()) { "Could not find certificates" }
    }

    val publicKey: PublicKey = certificates.first().publicKey
    val signatureAlgorithms = when (publicKey) {
        is RSAKey -> getSuggestedRsaAlgorithms(publicKey)
        is DSAKey -> getSuggestedDsaAlgorithms()
        else -> throw InvalidKeyException("Unsupported key algorithm: ${publicKey.algorithm}")
    }
    val requiredDigests = signatureAlgorithms.map { it.contentDigestAlgorithm }

    private fun getSuggestedRsaAlgorithms(key: RSAKey) = when {
        key.modulus.bitLength() <= 3072 -> listOf(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256)
        else -> listOf(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512)
    }

    private fun getSuggestedDsaAlgorithms() = listOf(SignatureAlgorithm.DSA_WITH_SHA256)
}