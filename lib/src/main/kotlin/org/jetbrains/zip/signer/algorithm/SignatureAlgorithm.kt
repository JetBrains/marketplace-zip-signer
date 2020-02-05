package org.jetbrains.zip.signer.algorithm

import com.android.apksig.internal.apk.ContentDigestAlgorithm
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

enum class SignatureAlgorithm(
    /**
     * Returns the ID of this signature algorithm as used in APK Signature Scheme v2 wire format.
     */
    val id: Int,
    /**
     * Returns the content digest algorithm associated with this signature algorithm.
     */
    val contentDigestAlgorithm: ContentDigestAlgorithm,
    /**
     * Returns the JCA [java.security.Key] algorithm used by this signature scheme.
     */
    val jcaKeyAlgorithm: String,
    /**
     * Returns the [java.security.Signature] algorithm and the [AlgorithmParameterSpec]
     * (or null if not needed) to parameterize the `Signature`.
     */
    val jcaSignatureAlgorithmAndParams: Pair<String, AlgorithmParameterSpec?>
) {
    // TODO reserve the 0x0000 ID to mean null
    /**
     * RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-256 in 1 MB chunks.
     */
    RSA_PSS_WITH_SHA256(
        0x0101,
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "RSA",
        "SHA256withRSA/PSS" to PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1
        )
    ),
    /**
     * RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-512 in 1 MB chunks.
     */
    RSA_PSS_WITH_SHA512(
        0x0102,
        ContentDigestAlgorithm.CHUNKED_SHA512,
        "RSA",
        "SHA512withRSA/PSS" to PSSParameterSpec(
            "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1
        )
    ),
    /** RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks.  */
    RSA_PKCS1_V1_5_WITH_SHA256(
        0x0103,
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "RSA",
        "SHA256withRSA" to null
    ),
    /** RSASSA-PKCS1-v1_5 with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks.  */
    RSA_PKCS1_V1_5_WITH_SHA512(
        0x0104,
        ContentDigestAlgorithm.CHUNKED_SHA512,
        "RSA",
        "SHA512withRSA" to null
    ),
    /** ECDSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks.  */
    ECDSA_WITH_SHA256(
        0x0201,
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "EC",
        "SHA256withECDSA" to null
    ),
    /** ECDSA with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks.  */
    ECDSA_WITH_SHA512(
        0x0202,
        ContentDigestAlgorithm.CHUNKED_SHA512,
        "EC",
        "SHA512withECDSA" to null
    ),
    /** DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks.  */
    DSA_WITH_SHA256(
        0x0301,
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "DSA",
        "SHA256withDSA" to null
    ),
    /**
     * RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in
     * the same way fsverity operates. This digest and the content length (before digestion, 8 bytes
     * in little endian) construct the final digest.
     */
    VERITY_RSA_PKCS1_V1_5_WITH_SHA256(
        0x0421,
        ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
        "RSA",
        "SHA256withRSA" to null
    ),
    /**
     * ECDSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way
     * fsverity operates. This digest and the content length (before digestion, 8 bytes in little
     * endian) construct the final digest.
     */
    VERITY_ECDSA_WITH_SHA256(
        0x0423,
        ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
        "EC",
        "SHA256withECDSA" to null
    ),
    /**
     * DSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way
     * fsverity operates. This digest and the content length (before digestion, 8 bytes in little
     * endian) construct the final digest.
     */
    VERITY_DSA_WITH_SHA256(
        0x0425,
        ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
        "DSA",
        "SHA256withDSA" to null
    );

    companion object {
        fun findById(id: Int) = values().find { it.id == id }
    }

}