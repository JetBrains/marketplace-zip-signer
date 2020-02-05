package org.jetbrains.zip.signer.verifier


import com.android.apksig.internal.apk.ApkSigningBlockUtils
import com.android.apksig.internal.apk.ApkSigningBlockUtils.SupportedSignature
import com.android.apksig.internal.apk.ApkSigningBlockUtils.toHex
import com.android.apksig.internal.apk.ContentDigestAlgorithm
import com.android.apksig.internal.util.ByteBufferDataSource
import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSource
import com.android.apksig.util.DataSources
import org.jetbrains.zip.signer.algorithm.SignatureAlgorithm.Companion.findById
import org.jetbrains.zip.signer.constants.SIGNATURE_SCHEME_BLOCK_ID
import org.jetbrains.zip.signer.exceptions.PluginFormatException
import org.jetbrains.zip.signer.exceptions.ZipFormatException
import org.jetbrains.zip.signer.signing.computeContentDigests
import org.jetbrains.zip.signer.zip.ZipUtils.findZipSections
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.zip.ZipException

object ZipVerifier {
    fun verify(file: File) {
        RandomAccessFile(file, "r").use {
            verify(
                DataSources.asDataSource(
                    it,
                    0,
                    it.length()
                )
            )
        }
    }

    private fun verify(dataSource: DataSource) {
        val zipSections = try {
            findZipSections(dataSource)
        } catch (e: ZipFormatException) {
            throw ZipException("Not a ZIP archive")
        }

        val signatureInfo = ApkSigningBlockUtils.findSignature(
            dataSource, zipSections,
            SIGNATURE_SCHEME_BLOCK_ID
        )
        val beforeApkSigningBlock = dataSource.slice(0, signatureInfo.apkSigningBlockOffset)
        val centralDir = dataSource.slice(
            signatureInfo.centralDirOffset,
            signatureInfo.eocdOffset - signatureInfo.centralDirOffset
        )
        val eocd = signatureInfo.eocd
        verify(
            beforeApkSigningBlock,
            signatureInfo.signatureBlock,
            centralDir,
            eocd
        )
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun verify(
        beforeApkSigningBlock: DataSource,
        apkSignatureSchemeV2Block: ByteBuffer,
        centralDir: DataSource,
        eocd: ByteBuffer
    ) {
        val contentDigestsToVerify = HashSet<ContentDigestAlgorithm>(1)
        val signers = parseSigners(
            apkSignatureSchemeV2Block,
            contentDigestsToVerify
        )
        verifyIntegrity(
            beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, signers
        )
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun parseSigners(
        apkSignatureSchemeV2Block: ByteBuffer,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): List<ApkSigningBlockUtils.Result.SignerInfo> {
        val signers: ByteBuffer =
            getLengthPrefixedSlice(
                apkSignatureSchemeV2Block
            )
        if (!signers.hasRemaining()) {
            return emptyList()
        }
        val certFactory: CertificateFactory
        certFactory = try {
            CertificateFactory.getInstance("X.509")
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to obtain X.509 CertificateFactory", e)
        }
        val result = mutableListOf<ApkSigningBlockUtils.Result.SignerInfo>()
        while (signers.hasRemaining()) {
            try {
                val signerBytes =
                    getLengthPrefixedSlice(signers)
                result.add(
                    parseSigner(
                        signerBytes,
                        certFactory,
                        contentDigestsToVerify
                    )
                )
            } catch (e: PluginFormatException) {
                throw e
            } catch (e: BufferUnderflowException) {
                throw e
            }
        }
        return result
    }

    @Throws(PluginFormatException::class, NoSuchAlgorithmException::class)
    private fun parseSigner(
        signerBlock: ByteBuffer,
        certFactory: CertificateFactory,
        contentDigestsToVerify: MutableSet<ContentDigestAlgorithm>
    ): ApkSigningBlockUtils.Result.SignerInfo {
        val result = ApkSigningBlockUtils.Result.SignerInfo()
        val signedData =
            getLengthPrefixedSlice(signerBlock)
        val signedDataBytes = ByteArray(signedData.remaining())
        signedData[signedDataBytes]
        signedData.flip()
        result.signedData = signedDataBytes
        val signatures =
            getLengthPrefixedSlice(signerBlock)
        val publicKeyBytes =
            readLengthPrefixedByteArray(signerBlock)
        // Parse the signatures block and identify supported signatures
        var signatureCount = 0
        val supportedSignatures: MutableList<SupportedSignature> =
            ArrayList(1)
        while (signatures.hasRemaining()) {
            signatureCount++
            try {
                val signature =
                    getLengthPrefixedSlice(signatures)
                val sigAlgorithmId = signature.int
                val sigBytes =
                    readLengthPrefixedByteArray(
                        signature
                    )
                result.signatures.add(
                    ApkSigningBlockUtils.Result.SignerInfo.Signature(
                        sigAlgorithmId, sigBytes
                    )
                )
                val signatureAlgorithm =
                    findById(sigAlgorithmId)
                if (signatureAlgorithm == null) {
                    result.addWarning(Issue.V2_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId)
                    continue
                }
                supportedSignatures.add(
                    SupportedSignature(signatureAlgorithm, sigBytes)
                )
            } catch (e: BufferUnderflowException) {
                result.addError(Issue.V2_SIG_MALFORMED_SIGNATURE, signatureCount)
                throw e;
            }
        }
        if (result.signatures.isEmpty()) {
            result.addError(Issue.V2_SIG_NO_SIGNATURES)
            return result
        }

        supportedSignatures.forEach { signature ->
            val signatureAlgorithm = signature.algorithm
            val jcaSignatureAlgorithm = signatureAlgorithm.jcaSignatureAlgorithmAndParams.first
            val jcaSignatureAlgorithmParams =
                signatureAlgorithm.jcaSignatureAlgorithmAndParams.second
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
                if (jcaSignatureAlgorithmParams != null) {
                    sig.setParameter(jcaSignatureAlgorithmParams)
                }
                signedData.position(0)
                sig.update(signedData)
                val sigBytes = signature.signature
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
        // At least one signature over signedData has verified. We can now parse signed-data.
        signedData.position(0)
        val digests =
            getLengthPrefixedSlice(signedData)
        val certificates =
            getLengthPrefixedSlice(signedData)
        val additionalAttributes =
            getLengthPrefixedSlice(signedData)
        // Parse the certificates block
        var certificateIndex = -1
        while (certificates.hasRemaining()) {
            certificateIndex++
            val encodedCert = readLengthPrefixedByteArray(certificates)
            val certificate = try {
                certFactory.generateCertificate(ByteArrayInputStream(encodedCert)) as X509Certificate
            } catch (e: CertificateException) {
                result.addError(
                    Issue.V2_SIG_MALFORMED_CERTIFICATE,
                    certificateIndex,
                    certificateIndex + 1,
                    e
                )
                return result
            }
            result.certs.add(certificate)
        }
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
        // Parse the digests block
        var digestCount = 0
        while (digests.hasRemaining()) {
            digestCount++
            try {
                val digest =
                    getLengthPrefixedSlice(digests)
                val sigAlgorithmId = digest.int
                val digestBytes =
                    readLengthPrefixedByteArray(digest)
                result.contentDigests.add(
                    ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                        sigAlgorithmId, digestBytes
                    )
                )
            } catch (e: BufferUnderflowException) {
                result.addError(Issue.V2_SIG_MALFORMED_DIGEST, digestCount)
                return result
            }
        }
        val sigAlgsFromSignaturesRecord: MutableList<Int> =
            ArrayList(result.signatures.size)
        for (signature in result.signatures) {
            sigAlgsFromSignaturesRecord.add(signature.algorithmId)
        }
        val sigAlgsFromDigestsRecord: MutableList<Int> =
            ArrayList(result.contentDigests.size)
        for (digest in result.contentDigests) {
            sigAlgsFromDigestsRecord.add(digest.signatureAlgorithmId)
        }
        if (sigAlgsFromSignaturesRecord != sigAlgsFromDigestsRecord) {
            result.addError(
                Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,
                sigAlgsFromSignaturesRecord,
                sigAlgsFromDigestsRecord
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
            // Special checks for the verity algorithm requirements.
            if (actualContentDigests.containsKey(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)) {
                if (beforeApkSigningBlock.size() % ApkSigningBlockUtils.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0L) {
                    throw RuntimeException(
                        "APK Signing Block is not aligned on 4k boundary: " +
                                beforeApkSigningBlock.size()
                    )
                }
                val centralDirOffset =
                    ZipUtils.getZipEocdCentralDirectoryOffset(eocd)
                val signingBlockSize = centralDirOffset - beforeApkSigningBlock.size()
                if (signingBlockSize % ApkSigningBlockUtils.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0L) {
                    throw RuntimeException(
                        "APK Signing Block size is not multiple of page size: " +
                                signingBlockSize
                    )
                }
            }
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
                val signatureAlgorithm =
                    findById(expected.signatureAlgorithmId) ?: continue
                val contentDigestAlgorithm = signatureAlgorithm.contentDigestAlgorithm
                // if the current digest algorithm is not in the list provided by the caller then
// ignore it; the signer may contain digests not recognized by the specified SDK
// range.
                if (!contentDigestAlgorithms.contains(contentDigestAlgorithm)) {
                    continue
                }
                val expectedDigest = expected.value
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


    fun readLengthPrefixedByteArray(buf: ByteBuffer): ByteArray? {
        val len = buf.int
        if (len < 0) {
            throw PluginFormatException("Negative length");
        } else if (len > buf.remaining()) {
            throw PluginFormatException(
                "Underflow while reading length-prefixed value. Length: " + len
                        + ", available: " + buf.remaining()
            );
        }
        val result = ByteArray(len)
        buf[result]
        return result
    }

    fun getLengthPrefixedSlice(source: ByteBuffer): ByteBuffer {
        if (source.remaining() < 4) {
            throw PluginFormatException(
                "Remaining buffer too short to contain length of length-prefixed field"
                        + ". Remaining: " + source.remaining()
            )
        }
        val len = source.int
        require(len >= 0) { "Negative length" }
        if (len > source.remaining()) {
            throw PluginFormatException(
                "Length-prefixed field longer than remaining buffer"
                        + ". Field length: " + len + ", remaining: " + source.remaining()
            )
        }
        return getByteBuffer(source, len)
    }

    /**
     * Relative *get* method for reading `size` number of bytes from the current
     * position of this buffer.
     *
     *
     * This method reads the next `size` bytes at this buffer's current position,
     * returning them as a `ByteBuffer` with start set to 0, limit and capacity set to
     * `size`, byte order set to this buffer's byte order; and then increments the position by
     * `size`.
     */
    private fun getByteBuffer(source: ByteBuffer, size: Int): ByteBuffer {
        require(size >= 0) { "size: $size" }
        val originalLimit = source.limit()
        val position = source.position()
        val limit = position + size
        if (limit < position || limit > originalLimit) {
            throw BufferUnderflowException()
        }
        source.limit(limit)
        return try {
            val result = source.slice()
            result.order(source.order())
            source.position(limit)
            result
        } finally {
            source.limit(originalLimit)
        }
    }

}