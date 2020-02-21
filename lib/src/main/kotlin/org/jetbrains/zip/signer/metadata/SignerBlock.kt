package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.SignerBlockProto

class SignerBlock private constructor(
    val encodedCertificates: List<ByteArray>,
    val signatures: List<SignatureData>,
    val encodedPublicKey: ByteArray,
    val protobufRepresentation: SignerBlockProto
) {
    constructor(protobufRepresentation: SignerBlockProto) : this(
        protobufRepresentation.certificatesList.map { it.toByteArray() },
        protobufRepresentation.signaturesList.map { SignatureData(it) },
        protobufRepresentation.publicKey.toByteArray(),
        protobufRepresentation
    )

    constructor(
        encodedCertificates: List<ByteArray>,
        signatures: List<SignatureData>,
        encodedPublicKey: ByteArray
    ) : this(
        encodedCertificates,
        signatures,
        encodedPublicKey,
        SignerBlockProto.newBuilder()
            .addAllCertificates(encodedCertificates.map { ByteString.copyFrom(it) })
            .addAllSignatures(signatures.map { it.protobufRepresentation })
            .setPublicKey(ByteString.copyFrom(encodedPublicKey))
            .build()
    )
}