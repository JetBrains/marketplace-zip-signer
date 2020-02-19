package org.jetbrains.zip.signer.verifier


import com.android.apksig.internal.apk.ApkSigningBlockUtils
import com.android.apksig.internal.apk.ApkSigningBlockUtils.toHex
import com.android.apksig.internal.util.ByteBufferDataSource
import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSource
import com.android.apksig.util.DataSources
import org.jetbrains.zip.signer.exceptions.SigningBlockNotFoundException
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.SignerBlock
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signing.computeContentDigests
import org.jetbrains.zip.signer.zip.ZipUtils.findZipSections
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.*

object ZipVerifier {
    fun verify(file: File): List<ApkSigningBlockUtils.Result.SignerInfo> {
        RandomAccessFile(file, "r").use {
            return verify(
                DataSources.asDataSource(
                    it,
                    0,
                    it.length()
                )
            )
        }
    }

    private fun verify(dataSource: DataSource): List<ApkSigningBlockUtils.Result.SignerInfo> {
        val zipSections = findZipSections(dataSource)
        val signingBlock = ZipMetadata.findInZip(dataSource, zipSections)
            ?: throw SigningBlockNotFoundException("Zip archive contains no valid signing block")
        val signingBlockStart = zipSections.zipCentralDirectoryOffset - signingBlock.size
        val beforeApkSigningBlock = dataSource.slice(0, signingBlockStart)
        val centralDir = dataSource.slice(
            zipSections.zipCentralDirectoryOffset,
            zipSections.zipEndOfCentralDirectoryOffset - zipSections.zipCentralDirectoryOffset
        )
        return verify(
            beforeApkSigningBlock,
            signingBlock,
            centralDir,
            zipSections.zipEndOfCentralDirectory
        )
    }

    private fun verify(
        beforeApkSigningBlock: DataSource,
        zipMetadata: ZipMetadata,
        centralDir: DataSource,
        eocd: ByteBuffer
    ): List<ApkSigningBlockUtils.Result.SignerInfo> {
        val contentDigestsToVerify = HashSet<ContentDigestAlgorithm>(1)
        val signers = parseSigners(
            zipMetadata,
            contentDigestsToVerify
        )
        verifyIntegrity(
            beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, signers
        )
        return signers
    }

    private fun parseSigners(
        zipMetadata: ZipMetadata,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): List<ApkSigningBlockUtils.Result.SignerInfo> {
        val certFactory: CertificateFactory
        certFactory = try {
            CertificateFactory.getInstance("X.509")
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to obtain X.509 CertificateFactory", e)
        }
        return zipMetadata.signers.map {
            parseSigner(it, certFactory, contentDigestsToVerify)
        }
    }

    private fun parseSigner(
        signer: SignerBlock,
        certFactory: CertificateFactory,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): ApkSigningBlockUtils.Result.SignerInfo {
        val result = ApkSigningBlockUtils.Result.SignerInfo()
        val signedData = signer.dataToSign

        val publicKeyBytes = signer.encodedPublicKey

        result.signatures.addAll(signer.signatures)
        if (result.signatures.isEmpty()) {
            result.addError(Issue.V2_SIG_NO_SIGNATURES)
            return result
        }

        signer.signatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithm

            val keyAlgorithm = signatureAlgorithm.jcaKeyAlgorithm
            val publicKey = try {
                KeyFactory.getInstance(keyAlgorithm).generatePublic(
                    X509EncodedKeySpec(publicKeyBytes)
                )
            } catch (e: Exception) {
                result.addError(Issue.V2_SIG_MALFORMED_PUBLIC_KEY, e)
                return result
            }
            try {
                val sig = Signature.getInstance(jcaSignatureAlgorithm)
                sig.initVerify(publicKey)
                sig.update(signedData.toByteArray())
                val sigBytes = signature.signatureBytes
                if (!sig.verify(sigBytes)) {
                    result.addError(Issue.V2_SIG_DID_NOT_VERIFY, signatureAlgorithm)
                    return result
                }
                result.verifiedSignatures[signatureAlgorithm] = sigBytes
                contentDigestsToVerify.add(signatureAlgorithm.contentDigestAlgorithm)
            } catch (e: InvalidKeyException) {
                result.addError(Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e)
                return result
            } catch (e: InvalidAlgorithmParameterException) {
                result.addError(Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e)
                return result
            } catch (e: SignatureException) {
                result.addError(Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e)
                return result
            }
        }

        result.certs.addAll(signedData.encodedCertificates.map {
            certFactory.generateCertificate(it.inputStream()) as X509Certificate
        })
        if (result.certs.isEmpty()) {
            result.addError(Issue.V2_SIG_NO_CERTIFICATES)
            return result
        }
        val mainCertificate = result.certs[0]
        val certificatePublicKeyBytes = mainCertificate.publicKey.encoded

        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            result.addError(
                Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,
                ApkSigningBlockUtils.toHex(certificatePublicKeyBytes),
                ApkSigningBlockUtils.toHex(publicKeyBytes)
            )
            return result
        }

        result.contentDigests.addAll(signer.dataToSign.digests)
        val digestAlgorithmsFromSignaturesRecord = result.signatures.map { it.algorithm.contentDigestAlgorithm }
        val digestAlgorithmsFromDigestsRecord = result.contentDigests.map { it.algorithm }
        if (digestAlgorithmsFromSignaturesRecord != digestAlgorithmsFromDigestsRecord) {
            result.addError(
                Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,
                digestAlgorithmsFromSignaturesRecord,
                digestAlgorithmsFromDigestsRecord
            )
            return result
        }
        return result
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    fun verifyIntegrity(
        beforeApkSigningBlock: DataSource,
        centralDir: DataSource,
        eocd: ByteBuffer,
        contentDigestAlgorithms: Set<ContentDigestAlgorithm>,
        signers: Collection<ApkSigningBlockUtils.Result.SignerInfo>
    ) {
        if (contentDigestAlgorithms.isEmpty()) { // This should never occur because this method is invoked once at least one signature
// is verified, meaning at least one content digest is known.
            throw RuntimeException("No content digests found")
        }
        // For the purposes of verifying integrity, ZIP End of Central Directory (EoCD) must be
// treated as though its Central Directory offset points to the start of APK Signing Block.
// We thus modify the EoCD accordingly.
        val modifiedEocd = ByteBuffer.allocate(eocd.remaining())
        val eocdSavedPos = eocd.position()
        modifiedEocd.order(ByteOrder.LITTLE_ENDIAN)
        modifiedEocd.put(eocd)
        modifiedEocd.flip()
        // restore eocd to position prior to modification in case it is to be used elsewhere
        eocd.position(eocdSavedPos)
        ZipUtils.setZipEocdCentralDirectoryOffset(
            modifiedEocd,
            beforeApkSigningBlock.size()
        )
        val actualContentDigests: Map<ContentDigestAlgorithm, ByteArray>
        try {
            actualContentDigests = computeContentDigests(
                contentDigestAlgorithms,
                beforeApkSigningBlock,
                centralDir,
                ByteBufferDataSource(modifiedEocd)
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
        for (signerInfo in signers) {
            for (expected in signerInfo.contentDigests) {
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
                                + " Expected: ${toHex(expectedDigest)}, actual: ${toHex(actualDigest)}"
                    )
                }
                signerInfo.verifiedContentDigests[contentDigestAlgorithm] = actualDigest
            }
        }
    }
}