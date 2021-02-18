package org.jetbrains.zip.signer.metadata

import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.proto.SignatureDataProto

enum class SignatureAlgorithm(
    val contentDigestAlgorithm: ContentDigestAlgorithm,
    val jcaKeyAlgorithm: String,
    val jcaSignatureAlgorithm: String
) {
    ECDSA_WITH_SHA384(
        ContentDigestAlgorithm.CHUNKED_SHA384,
        "ECDSA",
        "SHA384withECDSA"
    ),
    RSA_PKCS1_V1_5_WITH_SHA256(
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "RSA",
        "SHA256withRSA"
    ),
    RSA_PKCS1_V1_5_WITH_SHA512(
        ContentDigestAlgorithm.CHUNKED_SHA512,
        "RSA",
        "SHA512withRSA"
    ),
    DSA_WITH_SHA256(
        ContentDigestAlgorithm.CHUNKED_SHA256,
        "DSA",
        "SHA256withDSA"
    );

    companion object {
        fun fromProtobufEnum(protobufAlgorithmId: SignatureDataProto.AlgorithmId) = when (protobufAlgorithmId) {
            SignatureDataProto.AlgorithmId.ECDSA_WITH_SHA384 -> ECDSA_WITH_SHA384
            SignatureDataProto.AlgorithmId.RSA_WITH_SHA256 -> RSA_PKCS1_V1_5_WITH_SHA256
            SignatureDataProto.AlgorithmId.RSA_WITH_SHA512 -> RSA_PKCS1_V1_5_WITH_SHA512
            SignatureDataProto.AlgorithmId.DSA_WITH_SHA256 -> DSA_WITH_SHA256
            SignatureDataProto.AlgorithmId.UNRECOGNIZED -> throw IllegalArgumentException("Unknown signature type")
        }
    }

    fun toProtobufEnum() = when (this) {
        ECDSA_WITH_SHA384 -> SignatureDataProto.AlgorithmId.ECDSA_WITH_SHA384
        RSA_PKCS1_V1_5_WITH_SHA256 -> SignatureDataProto.AlgorithmId.RSA_WITH_SHA256
        RSA_PKCS1_V1_5_WITH_SHA512 -> SignatureDataProto.AlgorithmId.RSA_WITH_SHA512
        DSA_WITH_SHA256 -> SignatureDataProto.AlgorithmId.DSA_WITH_SHA256
    }

}