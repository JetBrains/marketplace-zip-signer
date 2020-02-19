package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.DataToSignProto

class DataToSign private constructor(
    val digests: List<Digest>, val encodedCertificates: List<ByteArray>, val protobufRepresentation: DataToSignProto
) {
    constructor(protobufRepresentation: DataToSignProto) : this(
        protobufRepresentation.digestsList.map { Digest(it) },
        protobufRepresentation.certificatesList.map { it.toByteArray() },
        protobufRepresentation
    )

    constructor(digests: List<Digest>, encodedCertificates: List<ByteArray>) : this(
        digests,
        encodedCertificates,
        DataToSignProto.newBuilder()
            .addAllDigests(digests.map { it.protobufRepresentation })
            .addAllCertificates(encodedCertificates.map { ByteString.copyFrom(it) })
            .build()
    )

    fun toByteArray() = protobufRepresentation.toByteArray()
}