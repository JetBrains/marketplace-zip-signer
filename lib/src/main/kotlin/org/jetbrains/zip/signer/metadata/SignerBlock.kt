package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.SignerBlockProto

internal class SignerBlock private constructor(
    val encodedCertificates: List<ByteArray>,
    val signatures: List<SignatureData>,
    val protobufRepresentation: SignerBlockProto
) {
    constructor(protobufRepresentation: SignerBlockProto) : this(
        protobufRepresentation.certificatesList.map { it.toByteArray() },
        protobufRepresentation.signaturesList.map { SignatureData(it) },
        protobufRepresentation
    )

    constructor(
        encodedCertificates: List<ByteArray>,
        signatures: List<SignatureData>
    ) : this(
        encodedCertificates,
        signatures,
        SignerBlockProto.newBuilder()
            .addAllCertificates(encodedCertificates.map { ByteString.copyFrom(it) })
            .addAllSignatures(signatures.map { it.protobufRepresentation })
            .build()
    )
}