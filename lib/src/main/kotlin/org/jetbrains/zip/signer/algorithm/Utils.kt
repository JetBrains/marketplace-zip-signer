package org.jetbrains.zip.signer.algorithm

import java.security.InvalidKeyException
import java.security.PublicKey
import java.security.interfaces.DSAKey
import java.security.interfaces.RSAKey

fun getSuggestedSignatureAlgorithms(
    signingKey: PublicKey
): List<SignatureAlgorithm> {
    val keyAlgorithm = signingKey.algorithm
    return when (signingKey) {
        is RSAKey -> getSuggestedRsaAlgorithms(signingKey)
        is DSAKey -> getSuggestedDsaAlgorithms()
        else -> throw InvalidKeyException("Unsupported key algorithm: $keyAlgorithm")
    }
}

private fun getSuggestedRsaAlgorithms(key: RSAKey) = when {
    key.modulus.bitLength() <= 3072 -> listOf(
        SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256//, SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256
    )
    else -> listOf(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512)
}

private fun getSuggestedDsaAlgorithms() = listOf(
    SignatureAlgorithm.DSA_WITH_SHA256
//    SignatureAlgorithm.VERITY_DSA_WITH_SHA256
)