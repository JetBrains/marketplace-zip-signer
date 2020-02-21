package org.jetbrains.zip.signer.verifier


import org.jetbrains.zip.signer.datasource.ByteBufferDataSource
import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.datasource.FileChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.exceptions.SigningBlockNotFoundException
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
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
            val contentDigestsToVerify = HashSet<ContentDigestAlgorithm>(1)
            val signers = verify(zipMetadata, contentDigestsToVerify)
            verifyIntegrity(beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, zipMetadata)
            VerificationSuccess(signers)
        } catch (e: ZipVerificationException) {
            VerificationFail(e)
        }

    }

    private fun verify(
        zipMetadata: ZipMetadata,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): List<List<Certificate>> {
        val certFactory = CertificateFactory.getInstance("X.509")
        return zipMetadata.signers.map {
            verify(it, certFactory, contentDigestsToVerify)
        }
    }

    private fun verify(
        signer: SignerBlock,
        certFactory: CertificateFactory,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): List<Certificate> {
        val signedData = signer.dataToSign

        val publicKeyBytes = signer.encodedPublicKey

        if (signer.signatures.isEmpty()) throw ZipVerificationException("Signer block contains no signatures")

        signer.signatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm

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
                sig.update(signedData.toByteArray())
                val sigBytes = signature.signatureBytes
                if (!sig.verify(sigBytes)) {
                    throw ZipVerificationException("Signature over signed-data did not verify")
                }
                contentDigestsToVerify.add(signatureAlgorithm.contentDigestAlgorithm)
            } catch (e: InvalidKeyException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            } catch (e: InvalidAlgorithmParameterException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            } catch (e: SignatureException) {
                throw ZipVerificationException("Signature over signed-data did not verify")
            }
        }

        val certificates = signedData.encodedCertificates.map {
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

        val digestAlgorithmsFromSignaturesRecord = signer.signatures.map { it.algorithm.contentDigestAlgorithm }
        val digestAlgorithmsFromDigestsRecord = signer.dataToSign.digests.map { it.algorithm }
        if (digestAlgorithmsFromSignaturesRecord != digestAlgorithmsFromDigestsRecord) {
            throw ZipVerificationException("Signature algorithms mismatch between signatures and digests records")
        }
        return certificates
    }

    fun verifyIntegrity(
        beforeApkSigningBlock: DataSource,
        centralDir: DataSource,
        eocd: DataSource,
        contentDigestAlgorithms: Set<ContentDigestAlgorithm>,
        zipMetadata: ZipMetadata
    ) {
        if (contentDigestAlgorithms.isEmpty()) {
            throw ZipVerificationException("No content digests found")
        }

        val modifiedEocd = eocd.getByteBuffer(0, eocd.size().toInt()).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }
        ZipUtils.setZipEocdCentralDirectoryOffset(modifiedEocd, beforeApkSigningBlock.size().toUInt())

        val actualContentDigests = try {
            DigestUtils.computeDigest(
                contentDigestAlgorithms.toList(),
                listOf(beforeApkSigningBlock, centralDir, ByteBufferDataSource(modifiedEocd))
            )
        } catch (e: DigestException) {
            throw ZipVerificationException("Failed to compute content digests")
        }

        if (contentDigestAlgorithms != actualContentDigests.keys) {
            throw ZipVerificationException("Mismatch between sets of requested and computed content digests")
        }

        zipMetadata.signers.map { it.dataToSign.digests }.flatten().forEach { expected ->
            val expectedDigest = expected.digestBytes
            val actualDigest = actualContentDigests[expected.algorithm]
            if (!Arrays.equals(expectedDigest, actualDigest)) {
                throw ZipVerificationException("ZIP integrity check failed. ${expected.algorithm}s digest mismatch.")
            }
        }
    }
}