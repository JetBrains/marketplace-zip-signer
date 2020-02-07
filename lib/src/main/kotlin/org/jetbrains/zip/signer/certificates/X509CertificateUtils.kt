package org.jetbrains.zip.signer.certificates

import org.bouncycastle.x509.X509V3CertificateGenerator
import org.jetbrains.zip.signer.bytes.getLengthPrefixedArray
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.DSAPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*
import javax.security.auth.x500.X500Principal

object X509CertificateUtils {
    fun loadCertificateFromFile(file: File): Collection<X509Certificate> {
        val certificateFactory = CertificateFactory.getInstance("X509")
        return certificateFactory.generateCertificates(file.inputStream().buffered()).map { it as X509Certificate }
    }

    fun loadOpenSshKeyAsDummyCertificate(file: File, privateKey: PrivateKey): X509Certificate {
        val base64Encoded = file.readText().substringAfter(" ").substringBefore(" ")
        val decodedKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Encoded))
        val algorithmName = String(decodedKeyByteBuffer.getLengthPrefixedArray())
            .removePrefix("ssh-")
            .toUpperCase()
        val publicKey = when (algorithmName) {
            "RSA" -> getSshRsaPublicKey(decodedKeyByteBuffer)
            "DSS" -> getSshDsaPublicKey(decodedKeyByteBuffer)
            else -> throw IllegalArgumentException("Unsupported public key algorithm $algorithmName")
        }

        return generateDummyCertificate(privateKey, publicKey)
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

    private fun generateDummyCertificate(privateKey: PrivateKey, publicKey: PublicKey): X509Certificate {
        val dummyName = X500Principal("CN=Dummy Certificate")

        val yesterday = Date.from(Instant.now().minus(Duration.ofDays(1)))
        val farAwayDate = Date.from(LocalDate.of(9999, 12, 31).atStartOfDay().toInstant(ZoneOffset.UTC))

        return X509V3CertificateGenerator().apply {
            setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
            setIssuerDN(dummyName)
            setNotBefore(yesterday)
            setNotAfter(farAwayDate)
            setSubjectDN(dummyName)
            setPublicKey(publicKey)
            when (privateKey) {
                is RSAPrivateKey -> setSignatureAlgorithm("SHA256WithRSAEncryption")
                is DSAPrivateKey -> setSignatureAlgorithm("SHA256WithDSA")
                else -> throw IllegalArgumentException("Unsupported private key type")
            }
        }.generate(privateKey)
    }
}