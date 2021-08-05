package org.jetbrains.zip.signer.verifier


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
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.DigestException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@ExperimentalUnsignedTypes
object ZipVerifier {
    /**
     * Entrypoint for the zip verification process.
     * This function reads zip signer block, checks file hash digest,
     * verifies signatures of hash digest and checks that certificate chains
     * provided in the metadata are valid (each certificate is signed by the next one).
     *
     * @see ZipVerificationResult to found information about the next steps
     *
     * @param file - zip archive file
     * @return verification result
     */
    @JvmStatic
    @Throws(IOException::class)
    fun verify(file: File): ZipVerificationResult = verify(file.toPath())

    /**
     * Entrypoint for the zip verification process.
     * This function reads zip signer block, checks file hash digest,
     * verifies signatures of hash digest and checks that certificate chains
     * provided in the metadata are valid (each certificate is signed by the next one).
     *
     * @see ZipVerificationResult to found information about the next steps
     *
     * @param path - path of zip archive file
     * @return verification result
     */
    @JvmStatic
    @Throws(IOException::class)
    fun verify(path: Path): ZipVerificationResult {
        return FileChannel.open(path, StandardOpenOption.READ).use { verify(FileChannelDataSource(it)) }
    }

    private fun verify(dataSource: DataSource): ZipVerificationResult {
        val zipSectionsInformation = findZipSectionsInformation(dataSource)
        val zipMetadata = ZipMetadata.findInZip(dataSource, zipSectionsInformation)
            ?: return MissingSignatureResult
        val zipSections = ZipUtils.findZipSections(dataSource, zipSectionsInformation, zipMetadata)
        return verify(zipSections, zipMetadata)
    }

    private fun verify(zipSections: ZipSections, zipMetadata: ZipMetadata): ZipVerificationResult {
        return try {
            checkDigests(zipSections, zipMetadata)
            val certificateChains = verifySignatures(zipMetadata)
            verifyCertificateChains(certificateChains)
            SuccessfulVerificationResult(certificateChains)
        } catch (e: ZipVerificationException) {
            InvalidSignatureResult(e.message)
        }
    }

    private fun verifyCertificateChains(certificateChains: List<List<Certificate>>) {
        if (certificateChains.any { CertificateUtils.isValidCertificateChain(it).not() }) {
            throw ZipVerificationException("One of signature blocks contains invalid certificate chain")
        }
    }

    private fun verifySignatures(zipMetadata: ZipMetadata): List<List<X509Certificate>> {
        val certFactory = CertificateFactory.getInstance("X.509")
        val digests = zipMetadata.digests.associateBy { it.algorithm }
        return zipMetadata.signers.map { verifySignatures(digests, it, certFactory) }
    }

    private fun verifySignatures(
        digests: Map<ContentDigestAlgorithm, Digest>,
        signer: SignerBlock,
        certFactory: CertificateFactory
    ): List<X509Certificate> {
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
        val actualContentDigests = try {
            DigestUtils.computeDigest(zipMetadata.digests.map { it.algorithm }, zipSections)
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