package org.jetbrains.zip.signer.keys

import org.jetbrains.zip.signer.utils.getLengthPrefixedArray
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.DSAPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*

object PublicKeyUtils {
    fun loadOpenSshKey(file: File): PublicKey {
        val base64Encoded = file.readText().substringAfter(" ").substringBefore(" ")
        val decodedKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Encoded))
        val algorithmName = String(decodedKeyByteBuffer.getLengthPrefixedArray())
            .removePrefix("ssh-")
            .toUpperCase()
        return when (algorithmName) {
            "RSA" -> getSshRsaPublicKey(decodedKeyByteBuffer)
            "DSS" -> getSshDsaPublicKey(decodedKeyByteBuffer)
            else -> throw IllegalArgumentException("Unsupported public key algorithm $algorithmName")
        }
    }

    private fun getSshRsaPublicKey(buffer: ByteBuffer): PublicKey {
        val publicExponent = BigInteger(buffer.getLengthPrefixedArray())
        val modulus = BigInteger(buffer.getLengthPrefixedArray())
        return KeyFactory
            .getInstance("RSA")
            .generatePublic(RSAPublicKeySpec(modulus, publicExponent))
    }

    private fun getSshDsaPublicKey(buffer: ByteBuffer): PublicKey {
        val p = BigInteger(buffer.getLengthPrefixedArray())
        val q = BigInteger(buffer.getLengthPrefixedArray())
        val g = BigInteger(buffer.getLengthPrefixedArray())
        val y = BigInteger(buffer.getLengthPrefixedArray())
        return KeyFactory
            .getInstance("DSA")
            .generatePublic(DSAPublicKeySpec(y, p, q, g))
    }
}