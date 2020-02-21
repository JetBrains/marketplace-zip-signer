package org.jetbrains.zip.signer.verifier


import org.jetbrains.zip.signer.datasource.ByteBufferDataSource
import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.datasource.FileChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.exceptions.SigningBlockNotFoundException
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.metadata.SignerBlock
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.zip.ZipUtils
import org.jetbrains.zip.signer.zip.ZipUtils.findZipSections
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteOrder
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.*

@ExperimentalUnsignedTypes
object ZipVerifier {
    /**
     * Verifies validity of signatures and returns certificates grouped by signer
     */
    fun verify(file: File): VerificationResult {
        RandomAccessFile(file, "r").use {
            return verify(FileChannelDataSource(it.channel))
        }
    }

    private fun verify(dataSource: DataSource): VerificationResult {
        val zipSections = findZipSections(dataSource)
        val signingBlock = ZipMetadata.findInZip(dataSource, zipSections)
            ?: throw SigningBlockNotFoundException("Zip archive contains no valid signing block")
        val beforeApkSigningBlock = dataSource.slice(
            0, zipSections.centralDirectoryOffset - signingBlock.size
        )
        val centralDir = dataSource.slice(
            zipSections.centralDirectoryOffset,
            zipSections.endOfCentralDirectoryOffset - zipSections.centralDirectoryOffset
        )
        val endOfCentralDirectory = dataSource.slice(
            zipSections.endOfCentralDirectoryOffset,
            zipSections.endOfCentralDirectorySizeBytes
        )
        return verify(beforeApkSigningBlock, signingBlock, centralDir, endOfCentralDirectory)
    }

    private fun verify(
        beforeApkSigningBlock: DataSource,
        zipMetadata: ZipMetadata,
        centralDir: DataSource,
        eocd: DataSource
    ): VerificationResult {
        return try {
            val requiredContentDigests = zipMetadata.signers.map { signer ->
                signer.signatures.map { it.algorithm.contentDigestAlgorithm }
            }.flatten().toSet()
            checkDigests(beforeApkSigningBlock, centralDir, eocd, requiredContentDigests, zipMetadata)
            val signers = verify(zipMetadata)
            VerificationSuccess(signers)
        } catch (e: ZipVerificationException) {
            VerificationFail(e)
        }

    }

    private fun verify(
        zipMetadata: ZipMetadata
    ): List<List<Certificate>> {
        val certFactory = CertificateFactory.getInstance("X.509")
        val digests = zipMetadata.digests.associateBy { it.algorithm }
        return zipMetadata.signers.map { verify(digests, it, certFactory) }
    }

    private fun verify(
        digests: Map<ContentDigestAlgorithm, Digest>,
        signer: SignerBlock,
        certFactory: CertificateFactory
    ): List<Certificate> {
        val publicKeyBytes = signer.encodedPublicKey

        if (signer.signatures.isEmpty()) throw ZipVerificationException("Signer block contains no signatures")

        signer.signatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm
            val digest = digests[signature.algorithm.contentDigestAlgorithm]
                ?: throw RuntimeException("Missing digest ${signature.algorithm.contentDigestAlgorithm}")

            val keyAlgorithm = signatureAlgorithm.jcaKeyAlgorithm
            val publicKey = try {
                KeyFactory.getInstance(keyAlgorithm).generatePublic(
                    X509EncodedKeySpec(publicKeyBytes)
                )
            } catch (e: Exception) {
                throw ZipVerificationException("Malformed public key")
            }
            try {
                val sig = Signature.getInstance(jcaSignatureAlgorithm)
                sig.initVerify(publicKey)
                sig.update(digest.digestBytes)
                signer.encodedCertificates.forEach { sig.update(it) }
                val sigBytes = signature.signatureBytes
                if (!sig.verify(sigBytes)) {
                    throw ZipVerificationException("Signature over signed-data did not verify")
                }
            } catch (e: InvalidKeyException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            } catch (e: InvalidAlgorithmParameterException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            } catch (e: SignatureException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            }
        }

        val certificates = signer.encodedCertificates.map {
            certFactory.generateCertificate(it.inputStream()) as X509Certificate
        }
        if (certificates.isEmpty()) {
            throw ZipVerificationException("Signer has no certificates")
        }

        val mainCertificate = certificates[0]
        val certificatePublicKeyBytes = mainCertificate.publicKey.encoded

        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            throw ZipVerificationException("Public key mismatch between certificate and signature record")
        }

        return certificates
    }

    fun checkDigests(
        beforeApkSigningBlock: DataSource,
        centralDir: DataSource,
        eocd: DataSource,
        requiredContentDigestAlgorithms: Set<ContentDigestAlgorithm>,
        zipMetadata: ZipMetadata
    ) {
        if (requiredContentDigestAlgorithms.isEmpty()) {
            throw ZipVerificationException("No content digests found")
        }

        val modifiedEocd = eocd.getByteBuffer(0, eocd.size().toInt()).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }
        ZipUtils.setZipEocdCentralDirectoryOffset(modifiedEocd, beforeApkSigningBlock.size().toUInt())

        val actualContentDigests = try {
            DigestUtils.computeDigest(
                requiredContentDigestAlgorithms.toList(),
                listOf(beforeApkSigningBlock, centralDir, ByteBufferDataSource(modifiedEocd))
            )
        } catch (e: DigestException) {
            throw ZipVerificationException("Failed to compute content digests")
        }

        actualContentDigests.forEach { digest ->
            val expectedDigest = zipMetadata.digests.find { it.algorithm == digest.algorithm }
                ?: throw ZipVerificationException("Missing ${digest.algorithm} digest in metadata")
            if (!expectedDigest.digestBytes.contentEquals(digest.digestBytes)) {
                throw ZipVerificationException("ZIP integrity check failed. ${digest.algorithm}s digest mismatch.")
            }
        }
    }
}