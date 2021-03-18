package org.jetbrains.zip.signer.signer

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.net.URI
import java.security.cert.*
import java.security.cert.Certificate
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*


object CertificateUtils {
    private val farAwayDate: Date = Date.from(
        LocalDate.of(9999, 12, 31).atStartOfDay().toInstant(ZoneOffset.UTC)
    )

    /**
     * Utility function to load X509 certificate from a file using the X509 CertificateFactory
     * @param file - file containing X509 certificates
     * @return certificates from file
     */
    @JvmStatic
    @Throws(CertificateException::class)
    fun loadCertificatesFromFile(file: File) = loadCertificates(file.readText())

    /**
     * Utility function to load X509 certificate from a string using the X509 CertificateFactory
     * @param certificate - string containing X509 certificates
     * @return loaded certificates
     */
    @JvmStatic
    @Throws(CertificateException::class)
    fun loadCertificates(certificate: String): List<X509Certificate> {
        val certificateFactory = CertificateFactory.getInstance("X509")
        return certificateFactory.generateCertificates(certificate.byteInputStream()).map { it as X509Certificate }
    }

    fun generateDummyCertificate(keyPair: PEMKeyPair): X509Certificate {
        val dummyName = X500Name("CN=Dummy Certificate")
        val yesterday = Date.from(Instant.now().minus(Duration.ofDays(1)))
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

    fun isValidCertificateChain(certs: List<Certificate>): Boolean {
        return certs.zipWithNext().all { it.first.isSignedBy(it.second) }
    }

    /**
     * Utility function to download CRLs for certificate chain. URLs of revocation lists are extracted from the
     * certificates CRL distribution point extension.
     * @see getCrlUris
     * Result of the function call should be used to find revoked certificates
     * @see findRevokedCertificate
     * @param certs - certificate chain, each certificate should by signed be the next one
     * @return - revocation lists, one for each certificate except CA
     * @throws IllegalArgumentException if the certificate has no or multiple CRL distribution points
     */
    @Suppress("unused")
    @JvmStatic
    fun getRevocationLists(certs: List<X509Certificate>): List<X509CRL> {
        val certsExceptCA = certs.subList(0, certs.size - 1)
        return certsExceptCA.map { certificate ->
            val crlUris = getCrlUris(certificate)
            if (crlUris.isEmpty()) throw IllegalArgumentException("CRL not found for certificate")
            if (crlUris.size > 1) throw IllegalArgumentException("Multiple CRL URI found in certificate")
            val crlURI = crlUris.first()
            val certificateFactory = CertificateFactory.getInstance("X.509")
            certificateFactory.generateCRL(crlURI.toURL().openConnection().getInputStream()) as X509CRL
        }
    }

    /**
     * Utility function to get CRL distribution points URLs from the certificate.
     * @param certificate - X509 certificate
     * @return URI extracted from CRL distribution points certificate extension
     */
    @JvmStatic
    fun getCrlUris(certificate: X509Certificate): List<URI> {
        val crlDistributionPointsBytes = certificate.getExtensionValue(Extension.cRLDistributionPoints.id)
        val derOctetString = ASN1InputStream(ByteArrayInputStream(crlDistributionPointsBytes)).use {
            it.readObject() as DEROctetString
        }
        val crlDistPoint = ASN1InputStream(ByteArrayInputStream(derOctetString.octets)).use {
            CRLDistPoint.getInstance(it.readObject())
        }
        val crlUris = mutableListOf<URI>()
        crlDistPoint.distributionPoints.forEach { distributionPoint ->
            val distributionPointName = distributionPoint.distributionPoint
            if (distributionPointName.type == DistributionPointName.FULL_NAME) {
                val generalNames = GeneralNames.getInstance(distributionPointName.name).names
                generalNames.forEach { generalName ->
                    if (generalName.tagNo == GeneralName.uniformResourceIdentifier) {
                        val url = DERIA5String.getInstance(generalName.name).string
                        crlUris.add(URI(url))
                    }
                }
            }
        }
        return crlUris
    }

    /**
     * This function should be used as a part of the certificate chain validity check.
     * It can not be used to detect revoked CA, this certificate can be revoked only by the user in the certificate manager
     * If returning value is not null then at least one of the certificates was revoked and an error should be reported
     * @param certs - certificate chain, each certificate should by signed be the next one
     * @param revocationLists - revocation lists, one for each certificate except CA.
     * The revocation list with index n should be signed by the certificate with index n+1.
     * @return first found revoked certificate starting from the top-level certificates, null if any.
     */
    @JvmStatic
    fun findRevokedCertificate(
        certs: List<X509Certificate>,
        revocationLists: List<X509CRL>
    ): X509Certificate? {
        if (revocationLists.size != certs.size - 1) {
            throw IllegalArgumentException(
                "Number of revocation lists should be one less than the number of certificates"
            )
        }
        return certs
            .zipWithNext()
            .zip(revocationLists) { certificates, revocationList ->
                Triple(certificates.first, certificates.second, revocationList)
            }
            .reversed()
            .find { (certificate, certificateAuthority, revocationList) ->
                isCertificateRevoked(certificate, certificateAuthority, revocationList)
            }?.first
    }

    private fun isCertificateRevoked(
        certificate: X509Certificate,
        certificateAuthority: X509Certificate,
        revocationList: X509CRL
    ): Boolean {
        if (!isCrlValid(revocationList, certificateAuthority)) {
            throw IllegalArgumentException("Invalid CRL provided")
        }
        if (revocationList.getRevokedCertificate(certificate) != null) {
            return true
        }
        return false
    }

    private fun isCrlValid(certificateRevocationList: X509CRL, certificateAuthority: X509Certificate): Boolean {
        if (certificateRevocationList.issuerDN != certificateAuthority.subjectDN) {
            return false
        }
        return try {
            certificateRevocationList.verify(certificateAuthority.publicKey)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun Certificate.isSignedBy(other: Certificate): Boolean {
        return try {
            this.verify(other.publicKey)
            true
        } catch (e: Exception) {
            false
        }
    }
}