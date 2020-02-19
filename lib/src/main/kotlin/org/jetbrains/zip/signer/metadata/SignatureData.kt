package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.SignatureDataProto

class SignatureData private constructor(
    val algorithmId: Int, val signatureBytes: ByteArray, val protobufRepresentation: SignatureDataProto
) {
    constructor(protobufRepresentation: SignatureDataProto) : this(
        protobufRepresentation.algorithmId,
        protobufRepresentation.signatureBytes.toByteArray(),
        protobufRepresentation
    )

    constructor(algorithmId: Int, signatureBytes: ByteArray) : this(
        algorithmId,
        signatureBytes,
        SignatureDataProto.newBuilder()
            .setAlgorithmId(algorithmId)
            .setSignatureBytes(ByteString.copyFrom(signatureBytes))
            .build()
    )
}