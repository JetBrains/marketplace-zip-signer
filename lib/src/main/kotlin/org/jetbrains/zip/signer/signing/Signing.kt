package org.jetbrains.zip.signer.signing

import com.android.apksig.internal.apk.ContentDigestAlgorithm
import com.android.apksig.util.DataSinks
import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.algorithm.SignatureAlgorithm
import java.io.IOException
import java.security.*
import java.security.cert.X509Certificate
import kotlin.collections.set


fun computeContentDigests(
    digestAlgorithms: Collection<ContentDigestAlgorithm>,
    beforeCentralDir: DataSource,
    centralDir: DataSource,
    eocd: DataSource
): Map<ContentDigestAlgorithm, ByteArray> {
    try {
        val oneMbChunkBasedAlgorithm = digestAlgorithms.filter {
            it == ContentDigestAlgorithm.CHUNKED_SHA256 || it == ContentDigestAlgorithm.CHUNKED_SHA512
        }
        return computeChunkContentDigests(
            oneMbChunkBasedAlgorithm, listOf(beforeCentralDir, centralDir, eocd)
        )
    } catch (e: IOException) {
        throw IOException("Failed to read APK being signed", e)
    } catch (e: DigestException) {
        throw SignatureException("Failed to compute digests of APK", e)
    }
}

/**
 * For each digest algorithm the result is computed as follows:
 * 1. Each segment of contents is split into consecutive chunks of 1 MB in size.
 *    The final chunk will be shorter iff the length of segment is not a multiple of 1 MB.
 *    No chunks are produced for empty (zero length) segments.
 * 2. The digest of each chunk is computed over the concatenation of byte 0xa5, the chunk's
 *    length in bytes (uint32 little-endian) and the chunk's contents.
 * 3. The output digest is computed over the concatenation of the byte 0x5a, the number of
 *    chunks (uint32 little-endian) and the concatenation of digests of chunks of all
 *    segments in-order.
 */
fun computeChunkContentDigests(
    digestAlgorithms: List<ContentDigestAlgorithm>,
    contents: List<DataSource>,
    maximumChunkSize: Long = 1024 * 1024 // 1MB
): Map<ContentDigestAlgorithm, ByteArray> {
    var chunkCountLong: Long = 0
    for (input in contents) {
        chunkCountLong += getChunkCount(
            input.size(),
            maximumChunkSize
        )
    }
    if (chunkCountLong > Int.MAX_VALUE) {
        throw DigestException("Input too long: $chunkCountLong chunks")
    }
    val chunkCount = chunkCountLong.toInt()
    val mds = arrayOfNulls<MessageDigest>(digestAlgorithms.size)
    val digestsOfChunks = arrayOfNulls<ByteArray>(digestAlgorithms.size)
    val digestOutputSizes = IntArray(digestAlgorithms.size)
    for (i in digestAlgorithms.indices) {
        val digestAlgorithm = digestAlgorithms[i]
        val digestOutputSizeBytes = digestAlgorithm.chunkDigestOutputSizeBytes
        digestOutputSizes[i] = digestOutputSizeBytes
        val concatenationOfChunkCountAndChunkDigests = ByteArray(5 + chunkCount * digestOutputSizeBytes)
        concatenationOfChunkCountAndChunkDigests[0] = 0x5a
        setUnsignedInt32LittleEndian(
            chunkCount, concatenationOfChunkCountAndChunkDigests, 1
        )
        digestsOfChunks[i] = concatenationOfChunkCountAndChunkDigests
        val jcaAlgorithm = digestAlgorithm.jcaMessageDigestAlgorithm
        mds[i] = MessageDigest.getInstance(jcaAlgorithm)
    }
    val mdSink = DataSinks.asDataSink(*mds)
    val chunkContentPrefix = ByteArray(5)
    chunkContentPrefix[0] = 0xa5.toByte()
    var chunkIndex = 0

    for (input in contents) {
        var inputOffset: Long = 0
        var inputRemaining = input.size()
        while (inputRemaining > 0) {
            val chunkSize = inputRemaining.coerceAtMost(maximumChunkSize).toInt()
            setUnsignedInt32LittleEndian(
                chunkSize,
                chunkContentPrefix,
                1
            )
            for (i in mds.indices) {
                mds[i]!!.update(chunkContentPrefix)
            }
            try {
                input.feed(inputOffset, chunkSize.toLong(), mdSink)
            } catch (e: IOException) {
                throw IOException("Failed to read chunk #$chunkIndex", e)
            }
            for (i in digestAlgorithms.indices) {
                val md = mds[i]
                val concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i]
                val expectedDigestSizeBytes = digestOutputSizes[i]
                val actualDigestSizeBytes = md!!.digest(
                    concatenationOfChunkCountAndChunkDigests,
                    5 + chunkIndex * expectedDigestSizeBytes,
                    expectedDigestSizeBytes
                )
                if (actualDigestSizeBytes != expectedDigestSizeBytes) {
                    throw RuntimeException(
                        "Unexpected output size of " + md.algorithm
                                + " digest: " + actualDigestSizeBytes
                    )
                }
            }
            inputOffset += chunkSize.toLong()
            inputRemaining -= chunkSize.toLong()
            chunkIndex++
        }
    }

    val outputContentDigests = HashMap<ContentDigestAlgorithm, ByteArray>()
    digestAlgorithms.forEachIndexed { i, digestAlgorithm ->
        val concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i]
        val md = mds[i]
        val digest = md!!.digest(concatenationOfChunkCountAndChunkDigests)
        outputContentDigests[digestAlgorithm] = digest
    }
    return outputContentDigests
}

fun getChunkCount(inputSize: Long, chunkSize: Long) = (inputSize + chunkSize - 1) / chunkSize

fun generateSignerBlock(
    certificates: List<X509Certificate>,
    privateKey: PrivateKey,
    signatureAlgorithms: Collection<SignatureAlgorithm>,
    contentDigests: Map<ContentDigestAlgorithm, ByteArray>
): SignerBlock {
    if (certificates.isEmpty()) {
        throw SignatureException("No certificates configured for signer")
    }
    val publicKey = certificates[0].publicKey
    val dataToSign = getDataToSign(
        certificates,
        signatureAlgorithms,
        contentDigests
    )
    val signatures = signatureAlgorithms.map {
        SignatureData(
            it.id, generateSignatureOverData(
                dataToSign.toByteArray(),
                privateKey,
                publicKey,
                it
            )
        )
    }

    return SignerBlock(
        dataToSign,
        signatures,
        publicKey.encoded
    )
}

/**
 * FORMAT:
 * length-prefixed sequence of length-prefixed digests:
 *   uint32: signature algorithm ID
 *   length-prefixed bytes: digest of contents
 * length-prefixed sequence of certificates:
 *   length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
 * length-prefixed sequence of length-prefixed additional attributes:
 *   uint32: ID
 *   (length - 4) bytes: value
 */
fun getDataToSign(
    certificates: List<X509Certificate>,
    signatureAlgorithms: Collection<SignatureAlgorithm>,
    contentDigests: Map<ContentDigestAlgorithm, ByteArray>
): DataToSign {
    val encodedCertificates = certificates.map { it.encoded }
    val digests = signatureAlgorithms.map {
        val contentDigestAlgorithm = it.contentDigestAlgorithm
        val contentDigest = contentDigests[contentDigestAlgorithm] ?: throw RuntimeException(
            "$contentDigestAlgorithm content digest for $it not computed"
        )
        Digest(it.id, contentDigest)
    }
    return DataToSign(
        digests,
        encodedCertificates
    )
}

fun generateSignatureOverData(
    data: ByteArray,
    privateKey: PrivateKey,
    publicKey: PublicKey,
    algorithm: SignatureAlgorithm
): ByteArray {
    val (jcaSignatureAlgorithm, jcaSignatureAlgorithmParams) = algorithm.jcaSignatureAlgorithmAndParams
    val signatureBytes = try {
        with(Signature.getInstance(jcaSignatureAlgorithm)) {
            initSign(privateKey)
            if (jcaSignatureAlgorithmParams != null) {
                setParameter(jcaSignatureAlgorithmParams)
            }
            update(data)
            sign()
        }
    } catch (e: InvalidKeyException) {
        throw InvalidKeyException("Failed to sign using $jcaSignatureAlgorithm", e)
    } catch (e: InvalidAlgorithmParameterException) {
        throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
    } catch (e: SignatureException) {
        throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
    }

    try {
        with(Signature.getInstance(jcaSignatureAlgorithm)) {
            initVerify(publicKey)
            if (jcaSignatureAlgorithmParams != null) {
                setParameter(jcaSignatureAlgorithmParams)
            }
            update(data)
            if (!verify(signatureBytes)) {
                throw SignatureException(
                    "Failed to verify generated "
                            + jcaSignatureAlgorithm
                            + " signature using public key from certificate"
                )
            }
        }
    } catch (e: InvalidKeyException) {
        throw InvalidKeyException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    } catch (e: InvalidAlgorithmParameterException) {
        throw SignatureException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    } catch (e: SignatureException) {
        throw SignatureException(
            "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate", e
        )
    }
    return signatureBytes
}

