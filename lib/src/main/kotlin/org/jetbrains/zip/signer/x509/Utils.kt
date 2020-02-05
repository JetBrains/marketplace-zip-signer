package org.jetbrains.zip.signer.x509

import org.bouncycastle.x509.X509V3CertificateGenerator
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*
import javax.security.auth.x500.X500Principal


fun generateDummyCertificate(privateKey: PrivateKey, publicKey: PublicKey): X509Certificate {
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