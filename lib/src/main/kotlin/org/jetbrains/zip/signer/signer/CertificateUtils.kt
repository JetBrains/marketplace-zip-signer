package org.jetbrains.zip.signer.signer

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*


object CertificateUtils {
    fun loadCertificatesFromFile(file: File): List<X509Certificate> {
        val certificateFactory = CertificateFactory.getInstance("X509")
        return certificateFactory.generateCertificates(file.inputStream().buffered()).map { it as X509Certificate }
    }

    fun generateDummyCertificate(keyPair: PEMKeyPair): X509Certificate {
        val dummyName = X500Name("CN=Dummy Certificate")
        val yesterday = Date.from(Instant.now().minus(Duration.ofDays(1)))
        val farAwayDate = Date.from(LocalDate.of(9999, 12, 31).atStartOfDay().toInstant(ZoneOffset.UTC))
        val contentSigner = when (val privateKey = PrivateKeyFactory.createKey(keyPair.privateKeyInfo)) {
            is RSAPrivateCrtKeyParameters -> BcRSAContentSignerBuilder(
                AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)
            ).build(privateKey)
            is DSAPrivateKeyParameters -> BcDSAContentSignerBuilder(
                AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa),
                AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)
            ).build(privateKey)
            else -> throw IllegalArgumentException("Unsupported key type: ${privateKey::class.java.simpleName}")
        }

        return JcaX509CertificateConverter()
            .getCertificate(
                X509v3CertificateBuilder(
                    dummyName,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    yesterday,
                    farAwayDate,
                    dummyName,
                    keyPair.publicKeyInfo
                ).build(contentSigner)
            )
    }

    fun isCertificateChainTrusted(certs: List<Certificate>, certificateAuthority: Certificate): Boolean {
        if (certs[0] == certificateAuthority) return true
        return try {
            certs[0].verify(certificateAuthority.publicKey)
            true
        } catch (e: Exception) {
            false
        }
    }
}