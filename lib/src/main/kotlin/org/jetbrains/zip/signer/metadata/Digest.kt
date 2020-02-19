package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.DigestProto

class Digest private constructor(
    val algorithmId: Int, val digestBytes: ByteArray, val protobufRepresentation: DigestProto
) {
    constructor(protobufRepresentation: DigestProto) : this(
        protobufRepresentation.algorithmId,
        protobufRepresentation.digestBytes.toByteArray(),
        protobufRepresentation
    )

    constructor(algorithmId: Int, digestBytes: ByteArray) : this(
        algorithmId,
        digestBytes,
        DigestProto.newBuilder()
            .setAlgorithmId(algorithmId)
            .setDigestBytes(ByteString.copyFrom(digestBytes))
            .build()
    )
}