package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import org.jetbrains.zip.signer.utils.getLengthPrefixedArray
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.DSAKey
import java.security.interfaces.RSAKey
import java.security.spec.DSAPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*

object PublicKeyUtils {
    private enum class SupportedPublicKeysAlgorithms(val openSshName: String) {
        RSA("RSA"), DSA("DSS");
    }

    private val veryHighStrengthKeySize = 3072

    fun loadOpenSshKey(file: File): PublicKey {
        val base64Encoded = file.readText().substringAfter(" ").substringBefore(" ")
        val decodedKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Encoded))
        val algorithmName = String(decodedKeyByteBuffer.getLengthPrefixedArray())
            .removePrefix("ssh-")
            .toUpperCase()
        return when (algorithmName) {
            SupportedPublicKeysAlgorithms.RSA.openSshName -> getSshRsaPublicKey(decodedKeyByteBuffer)
            SupportedPublicKeysAlgorithms.DSA.openSshName -> getSshDsaPublicKey(decodedKeyByteBuffer)
            else -> throw IllegalArgumentException("Unsupported public key algorithm $algorithmName")
        }
    }

    fun getSuggestedSignatureAlgorithm(publicKey: PublicKey) = when (publicKey) {
        is RSAKey -> getSuggestedRsaAlgorithm(publicKey)
        is DSAKey -> SignatureAlgorithm.DSA_WITH_SHA256
        else -> throw InvalidKeyException("Unsupported key algorithm: ${publicKey.algorithm}")
    }

    private fun getSshRsaPublicKey(buffer: ByteBuffer): PublicKey {
        val publicExponent = BigInteger(buffer.getLengthPrefixedArray())
        val modulus = BigInteger(buffer.getLengthPrefixedArray())
        return KeyFactory
            .getInstance("RSA")
            .generatePublic(RSAPublicKeySpec(modulus, publicExponent))
    }

    private fun getSshDsaPublicKey(buffer: ByteBuffer): PublicKey {
        val prime = BigInteger(buffer.getLengthPrefixedArray())
        val subPrime = BigInteger(buffer.getLengthPrefixedArray())
        val base = BigInteger(buffer.getLengthPrefixedArray())
        val publicKey = BigInteger(buffer.getLengthPrefixedArray())
        return KeyFactory
            .getInstance("DSA")
            .generatePublic(DSAPublicKeySpec(publicKey, prime, subPrime, base))
    }

    private fun getSuggestedRsaAlgorithm(key: RSAKey) = when {
        key.modulus.bitLength() <= veryHighStrengthKeySize -> SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256
        else -> SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512
    }
}