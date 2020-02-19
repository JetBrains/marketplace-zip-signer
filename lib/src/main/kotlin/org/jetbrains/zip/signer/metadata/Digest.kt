package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.DigestProto

class Digest private constructor(
    val algorithm: ContentDigestAlgorithm, val digestBytes: ByteArray, val protobufRepresentation: DigestProto
) {
    constructor(protobufRepresentation: DigestProto) : this(
        ContentDigestAlgorithm.fromProtobufEnum(protobufRepresentation.algorithmId),
        protobufRepresentation.digestBytes.toByteArray(),
        protobufRepresentation
    )

    constructor(algorithm: ContentDigestAlgorithm, digestBytes: ByteArray) : this(
        algorithm,
        digestBytes,
        DigestProto.newBuilder()
            .setAlgorithmId(algorithm.toProtobufEnum())
            .setDigestBytes(ByteString.copyFrom(digestBytes))
            .build()
    )
}