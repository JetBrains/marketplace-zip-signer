package org.jetbrains.zip.signer.metadata

import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.SignerBlockProto

class SignerBlock private constructor(
    val dataToSign: DataToSign,
    val signatures: List<SignatureData>,
    val encodedPublicKey: ByteArray,
    val protobufRepresentation: SignerBlockProto
) {
    constructor(protobufRepresentation: SignerBlockProto) : this(
        DataToSign(protobufRepresentation.dataToSign),
        protobufRepresentation.signaturesList.map { SignatureData(it) },
        protobufRepresentation.publicKey.toByteArray(),
        protobufRepresentation
    )

    constructor(dataToSign: DataToSign, signatures: List<SignatureData>, encodedPublicKey: ByteArray) : this(
        dataToSign,
        signatures,
        encodedPublicKey,
        SignerBlockProto.newBuilder()
            .setDataToSign(dataToSign.protobufRepresentation)
            .addAllSignatures(signatures.map { it.protobufRepresentation })
            .setPublicKey(ByteString.copyFrom(encodedPublicKey))
            .build()
    )
}