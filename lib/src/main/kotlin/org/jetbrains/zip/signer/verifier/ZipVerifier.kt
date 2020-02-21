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
import org.jetbrains.zip.signer.utils.toHexString
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
    fun verify(file: File): List<Result<List<Certificate>>> {
        RandomAccessFile(file, "r").use {
            return verify(FileChannelDataSource(it.channel))
        }
    }

    private fun verify(dataSource: DataSource): List<Result<List<Certificate>>> {
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
    ): List<Result<List<Certificate>>> {
        val contentDigestsToVerify = HashSet<ContentDigestAlgorithm>(1)
        val signers = parseSigners(
            zipMetadata,
            contentDigestsToVerify
        )
        verifyIntegrity(
            beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, zipMetadata
        )
        return signers
    }

    private fun parseSigners(
        zipMetadata: ZipMetadata,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): List<Result<List<Certificate>>> {
        val certFactory = CertificateFactory.getInstance("X.509")
        return zipMetadata.signers.map {
            verifySigner(it, certFactory, contentDigestsToVerify)
        }
    }

    private fun verifySigner(
        signer: SignerBlock,
        certFactory: CertificateFactory,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): Result<List<Certificate>> {
        val signedData = signer.dataToSign

        val publicKeyBytes = signer.encodedPublicKey

        if (signer.signatures.isEmpty()) return Result.failure(
            ZipVerificationException("Signer block contains no signatures")
        )

        signer.signatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm

            val keyAlgorithm = signatureAlgorithm.jcaKeyAlgorithm
            val publicKey = try {
                KeyFactory.getInstance(keyAlgorithm).generatePublic(
                    X509EncodedKeySpec(publicKeyBytes)
                )
            } catch (e: Exception) {
                return Result.failure(ZipVerificationException("Malformed public key"))
            }
            try {
                val sig = Signature.getInstance(jcaSignatureAlgorithm)
                sig.initVerify(publicKey)
                sig.update(signedData.toByteArray())
                val sigBytes = signature.signatureBytes
                if (!sig.verify(sigBytes)) {
                    return Result.failure(ZipVerificationException("Signature over signed-data did not verify"))
                }
                contentDigestsToVerify.add(signatureAlgorithm.contentDigestAlgorithm)
            } catch (e: InvalidKeyException) {
                return Result.failure(ZipVerificationException("Signature over signed-data did not verify"))
            } catch (e: InvalidAlgorithmParameterException) {
                return Result.failure(ZipVerificationException("Signature over signed-data did not verify"))
            } catch (e: SignatureException) {
                return Result.failure(ZipVerificationException("Signature over signed-data did not verify"))
            }
        }

        val certificates = signedData.encodedCertificates.map {
            certFactory.generateCertificate(it.inputStream()) as X509Certificate
        }
        if (certificates.isEmpty()) {
            return Result.failure(ZipVerificationException("Signer has no certificates"))
        }

        val mainCertificate = certificates[0]
        val certificatePublicKeyBytes = mainCertificate.publicKey.encoded

        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            return Result.failure(
                ZipVerificationException("Public key mismatch between certificate and signature record")
            )
        }

        val digestAlgorithmsFromSignaturesRecord = signer.signatures.map { it.algorithm.contentDigestAlgorithm }
        val digestAlgorithmsFromDigestsRecord = signer.dataToSign.digests.map { it.algorithm }
        if (digestAlgorithmsFromSignaturesRecord != digestAlgorithmsFromDigestsRecord) {
            return Result.failure(
                ZipVerificationException("Signature algorithms mismatch between signatures and digests records")
            )
        }
        return Result.success(certificates)
    }

    fun verifyIntegrity(
        beforeApkSigningBlock: DataSource,
        centralDir: DataSource,
        eocd: DataSource,
        contentDigestAlgorithms: Set<ContentDigestAlgorithm>,
        zipMetadata: ZipMetadata
    ) {
        if (contentDigestAlgorithms.isEmpty()) { // This should never occur because this method is invoked once at least one signature
// is verified, meaning at least one content digest is known.
            throw RuntimeException("No content digests found")
        }
        // For the purposes of verifying integrity, ZIP End of Central Directory (EoCD) must be
// treated as though its Central Directory offset points to the start of APK Signing Block.
// We thus modify the EoCD accordingly.
        val modifiedEocd = eocd.getByteBuffer(0, eocd.size().toInt()).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }
        ZipUtils.setZipEocdCentralDirectoryOffset(
            modifiedEocd,
            beforeApkSigningBlock.size().toUInt()
        )
        val actualContentDigests: Map<ContentDigestAlgorithm, ByteArray>
        try {
            actualContentDigests = DigestUtils.computeDigest(
                contentDigestAlgorithms.toList(),
                listOf(
                    beforeApkSigningBlock,
                    centralDir,
                    ByteBufferDataSource(modifiedEocd)
                )
            )
        } catch (e: DigestException) {
            throw RuntimeException("Failed to compute content digests", e)
        }
        if (contentDigestAlgorithms != actualContentDigests.keys) {
            throw RuntimeException(
                "Mismatch between sets of requested and computed content digests"
                        + " . Requested: " + contentDigestAlgorithms
                        + ", computed: " + actualContentDigests.keys
            )
        }
        // Compare digests computed over the rest of APK against the corresponding expected digests
// in signer blocks.
        for (signerInfo in zipMetadata.signers) {
            for (expected in signerInfo.dataToSign.digests) {
                val contentDigestAlgorithm = expected.algorithm
                // if the current digest algorithm is not in the list provided by the caller then
// ignore it; the signer may contain digests not recognized by the specified SDK
// range.
                if (!contentDigestAlgorithms.contains(contentDigestAlgorithm)) {
                    continue
                }
                val expectedDigest = expected.digestBytes
                val actualDigest = actualContentDigests[contentDigestAlgorithm]
                if (!Arrays.equals(expectedDigest, actualDigest)) {
                    throw Exception(
                        "APK integrity check failed. ${contentDigestAlgorithm}s digest mismatch."
                                + " Expected: ${expectedDigest.toHexString()}, actual: ${actualDigest?.toHexString()}"
                    )
                }
            }
        }
    }
}