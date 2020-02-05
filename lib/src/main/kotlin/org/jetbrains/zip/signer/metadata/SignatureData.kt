package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.SignatureDataProto

internal class SignatureData private constructor(
    val algorithm: SignatureAlgorithm, val signatureBytes: ByteArray, val protobufRepresentation: SignatureDataProto
) {
    constructor(protobufRepresentation: SignatureDataProto) : this(
        SignatureAlgorithm.fromProtobufEnum(protobufRepresentation.algorithmId),
        protobufRepresentation.signatureBytes.toByteArray(),
        protobufRepresentation
    )

    constructor(algorithm: SignatureAlgorithm, signatureBytes: ByteArray) : this(
        algorithm,
        signatureBytes,
        SignatureDataProto.newBuilder()
            .setAlgorithmId(algorithm.toProtobufEnum())
            .setSignatureBytes(ByteString.copyFrom(signatureBytes))
            .build()
    )
}