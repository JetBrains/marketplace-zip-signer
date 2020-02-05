package org.jetbrains.zip.signer.verifier


import org.jetbrains.zip.signer.datasource.ByteBufferDataSource
import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.datasource.FileChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.metadata.SignerBlock
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.zip.ZipSections
import org.jetbrains.zip.signer.zip.ZipUtils
import org.jetbrains.zip.signer.zip.ZipUtils.findZipSectionsInformation
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteOrder
import java.security.DigestException
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@ExperimentalUnsignedTypes
object ZipVerifier {
    /**
     * Verifies validity of signatures and digests and checks that
     * certificates of at least one signer are signed with provided CA
     */
    @JvmStatic
    fun verify(file: File, certificateAuthority: Certificate) {
        val certificateChains = verify(file)
        certificateChains.find { CertificateUtils.isCertificateChainTrusted(it, certificateAuthority) }
            ?: throw ZipVerificationException("Zip archive was not signed with certificate signed by provided authority")
    }

    /**
     * Verifies validity of signatures and digests and checks that
     * public key of at least one signer is contained in provided list
     */
    @JvmStatic
    fun verify(file: File, publicKeys: List<PublicKey>) {
        val certificateChains = verify(file)
        certificateChains.find { publicKeys.contains(it.first().publicKey) }
            ?: throw ZipVerificationException("Zip archive was not signed with any of provided public keys")
    }

    private fun verify(file: File): List<List<Certificate>> {
        RandomAccessFile(file, "r").use {
            return verify(FileChannelDataSource(it.channel))
        }
    }

    private fun verify(dataSource: DataSource): List<List<Certificate>> {
        val zipSectionsInformation = findZipSectionsInformation(dataSource)
        val zipMetadata = ZipMetadata.findInZip(dataSource, zipSectionsInformation)
            ?: throw ZipVerificationException("Zip archive contains no valid signing block")
        val zipSections = ZipUtils.findZipSections(dataSource, zipSectionsInformation, zipMetadata)
        return verify(zipSections, zipMetadata)
    }

    private fun verify(zipSections: ZipSections, zipMetadata: ZipMetadata): List<List<Certificate>> {
        checkDigests(zipSections, zipMetadata)
        val certificateChains = verifySignatures(zipMetadata)
        verifyCertificateChains(certificateChains)
        return certificateChains
    }

    private fun verifyCertificateChains(certificateChains: List<List<Certificate>>) {
        if (certificateChains.any { CertificateUtils.isValidCertificateChain(it).not() }) {
            throw ZipVerificationException("One of signature blocks contains invalid certificate chain")
        }
    }

    private fun verifySignatures(zipMetadata: ZipMetadata): List<List<Certificate>> {
        val certFactory = CertificateFactory.getInstance("X.509")
        val digests = zipMetadata.digests.associateBy { it.algorithm }
        return zipMetadata.signers.map { verifySignatures(digests, it, certFactory) }
    }

    private fun verifySignatures(
        digests: Map<ContentDigestAlgorithm, Digest>,
        signer: SignerBlock,
        certFactory: CertificateFactory
    ): List<Certificate> {
        if (signer.signatures.isEmpty()) throw ZipVerificationException("Signer block contains no signatures")

        val certificates = signer.encodedCertificates.map {
            certFactory.generateCertificate(it.inputStream()) as X509Certificate
        }
        if (certificates.isEmpty()) {
            throw ZipVerificationException("Signer has no certificates")
        }

        signer.signatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val digest = digests[signature.algorithm.contentDigestAlgorithm]
                ?: throw ZipVerificationException("Missing digest ${signature.algorithm.contentDigestAlgorithm}")
            DefaultSignatureVerifier(certificates, signatureAlgorithm)
                .verify(digest.digestBytes, signature.signatureBytes)
        }

        return certificates
    }

    internal fun checkDigests(zipSections: ZipSections, zipMetadata: ZipMetadata) {
        val modifiedEocd = zipSections.endOfCentralDirectorySection
            .getByteBuffer(0, zipSections.endOfCentralDirectorySection.size().toInt())
            .apply {
                order(ByteOrder.LITTLE_ENDIAN)
            }
        ZipUtils.setZipEocdCentralDirectoryOffset(modifiedEocd, zipSections.beforeSigningBlockSection.size().toUInt())

        val actualContentDigests = try {
            DigestUtils.computeDigest(
                zipMetadata.digests.map { it.algorithm },
                listOf(
                    zipSections.beforeSigningBlockSection,
                    zipSections.centralDirectorySection,
                    ByteBufferDataSource(modifiedEocd)
                )
            )
        } catch (e: DigestException) {
            throw ZipVerificationException("Failed to compute content digests")
        }

        actualContentDigests.forEach { digest ->
            val expectedDigest = zipMetadata.digests.find { it.algorithm == digest.algorithm }
                ?: throw RuntimeException("Missing ${digest.algorithm} digest in metadata")
            if (!expectedDigest.digestBytes.contentEquals(digest.digestBytes)) {
                throw ZipVerificationException("ZIP integrity check failed. ${digest.algorithm}s digest mismatch.")
            }
        }
    }
}