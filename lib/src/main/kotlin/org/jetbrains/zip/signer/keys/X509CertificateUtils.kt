package org.jetbrains.zip.signer.keys

import org.bouncycastle.x509.X509V3CertificateGenerator
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*
import javax.security.auth.x500.X500Principal

object X509CertificateUtils {
    fun loadCertificatesFromFile(file: File): List<X509Certificate> {
        val certificateFactory = CertificateFactory.getInstance("X509")
        return certificateFactory.generateCertificates(file.inputStream().buffered()).map { it as X509Certificate }
    }

    fun generateDummyCertificate(keyPair: KeyPair): X509Certificate {
        val dummyName = X500Principal("CN=Dummy Certificate")

        val yesterday = Date.from(Instant.now().minus(Duration.ofDays(1)))
        val farAwayDate = Date.from(LocalDate.of(9999, 12, 31).atStartOfDay().toInstant(ZoneOffset.UTC))

        return X509V3CertificateGenerator().apply {
            setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
            setIssuerDN(dummyName)
            setNotBefore(yesterday)
            setNotAfter(farAwayDate)
            setSubjectDN(dummyName)
            setPublicKey(keyPair.public)
            when (keyPair.private) {
                is RSAPrivateKey -> setSignatureAlgorithm("SHA256WithRSAEncryption")
                is DSAPrivateKey -> setSignatureAlgorithm("SHA256WithDSA")
                else -> throw IllegalArgumentException("Unsupported private key type")
            }
        }.generate(keyPair.private)
    }
}