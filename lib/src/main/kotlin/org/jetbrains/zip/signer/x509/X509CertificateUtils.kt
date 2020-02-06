package org.jetbrains.zip.signer.x509

import org.bouncycastle.x509.X509V3CertificateGenerator
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
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
        val algorithmNameBytes = String(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val publicExponent = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val modulus = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )

        val publicKey = KeyFactory
            .getInstance("RSA")
            .generatePublic(RSAPublicKeySpec(modulus, publicExponent))
        return generateDummyCertificate(privateKey, publicKey)
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
            setSignatureAlgorithm("SHA256WithRSAEncryption")
        }.generate(privateKey)
    }

    private fun readDataFromSshRsa(buffer: ByteBuffer): ByteArray {
        val dataLength = buffer.int
        val data = ByteArray(dataLength)
        buffer.get(data)
        return data
    }
}