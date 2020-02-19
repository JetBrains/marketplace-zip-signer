package org.jetbrains.zip.signer.algorithm

import com.android.apksig.internal.apk.ContentDigestAlgorithm
import java.security.spec.AlgorithmParameterSpec

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
    /** DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks.  */
    DSA_WITH_SHA256(
        0x0301,
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "DSA",
        "SHA256withDSA" to null
    );

    companion object {
        fun findById(id: Int) = values().find { it.id == id }
    }

}