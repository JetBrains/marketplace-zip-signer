package org.jetbrains.zip.signer.signing

import com.android.apksig.util.DataSource
import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.proto.*
import org.jetbrains.zip.signer.zip.ZipSections
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ZipMetadata private constructor(
    val signers: List<SignerBlock>,
    private val protobufRepresentation: ZipMetadataProto
) {
    companion object {
        private const val SIGNATURE_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
        private const val SIGNATURE_BLOCK_MAGIC_LO = 0x20676953204b5040L
        private const val signatureBlockHeaderSize = 8
        private const val signatureBlockFooterSize = 24
        private const val signatureBlockMetadataSize = signatureBlockHeaderSize + signatureBlockFooterSize

        fun findInZip(zipArchive: DataSource, zipSections: ZipSections): ZipMetadata? {
            val centralDirStartOffset = zipSections.zipCentralDirectoryOffset
            if (centralDirStartOffset < signatureBlockMetadataSize) return null

            val footer = zipArchive
                .getByteBuffer(centralDirStartOffset - signatureBlockFooterSize, signatureBlockFooterSize)
                .apply {
                    order(ByteOrder.LITTLE_ENDIAN)
                }
            if (footer.getLong(8) != SIGNATURE_BLOCK_MAGIC_LO || footer.getLong(16) != SIGNATURE_BLOCK_MAGIC_HI) {
                return null
            }

            val signatureBlockSizeInFooter = footer.getLong(0)
            if (signatureBlockSizeInFooter < footer.capacity() || signatureBlockSizeInFooter > Int.MAX_VALUE - 8) {
                return null
            }
            val totalSize = (signatureBlockSizeInFooter + 8).toInt()
            val signingBlockOffset = centralDirStartOffset - totalSize
            if (signingBlockOffset < 0) return null
            val signatureBlockHeader = zipArchive.getByteBuffer(signingBlockOffset, signatureBlockHeaderSize).apply {
                order(ByteOrder.LITTLE_ENDIAN)
            }
            val signatureBlockSizeInHeader = signatureBlockHeader.getLong(0)
            if (signatureBlockSizeInHeader != signatureBlockSizeInFooter) return null


            val protobufContent = ZipMetadataProto.parseFrom(
                zipArchive.getByteBuffer(
                    signingBlockOffset + signatureBlockHeaderSize, totalSize - signatureBlockMetadataSize
                )
            )
            assert(protobufContent.signatureSchemeVersion == 1)
            return ZipMetadata(protobufContent.content.signersList.map { SignerBlock(it) }, protobufContent)
        }

        fun fromSignerBlocks(signers: List<SignerBlock>): ZipMetadata {
            return ZipMetadata(
                signers,
                ZipMetadataProto
                    .newBuilder()
                    .setSignatureSchemeVersion(1)
                    .setContent(
                        ZipSignatureBlockProto
                            .newBuilder()
                            .addAllSigners(signers.map { it.protobufRepresentation })
                            .build()
                    )
                    .build()
            )
        }
    }

    val size = signatureBlockMetadataSize + protobufRepresentation.serializedSize

    fun toByteArray(): ByteArray {
        return with(ByteBuffer.allocate(size)) {
            order(ByteOrder.LITTLE_ENDIAN)
            val blockSizeFieldValue = size - 8L
            putLong(blockSizeFieldValue)
            put(protobufRepresentation.toByteArray())
            putLong(blockSizeFieldValue)
            putLong(SIGNATURE_BLOCK_MAGIC_LO)
            putLong(SIGNATURE_BLOCK_MAGIC_HI)
            array()
        }
    }
}

class SignerBlock private constructor(
    val dataToSign: DataToSign,
    val signatures: List<SignatureData>,
    val encodedPublicKey: ByteArray,
    val protobufRepresentation: SignerBlockProto
) {
    constructor(protobufedContent: SignerBlockProto) : this(
        DataToSign(protobufedContent.dataToSign),
        protobufedContent.signaturesList.map { SignatureData(it) },
        protobufedContent.publicKey.toByteArray(),
        protobufedContent
    )

    constructor(dataToSign: DataToSign, signatures: List<SignatureData>, encodedPublicKey: ByteArray) : this(
        dataToSign,
        signatures,
        encodedPublicKey,
        SignerBlockProto
            .newBuilder()
            .setDataToSign(dataToSign.protobufedContent)
            .addAllSignatures(signatures.map { it.protobufedContent })
            .setPublicKey(ByteString.copyFrom(encodedPublicKey))
            .build()
    )
}

class DataToSign private constructor(
    val digests: List<Digest>, val encodedCertificates: List<ByteArray>, val protobufedContent: DataToSignProto
) {
    constructor(protobufedContent: DataToSignProto) : this(
        protobufedContent.digestsList.map { Digest(it) },
        protobufedContent.certificatesList.map { it.toByteArray() },
        protobufedContent
    )

    constructor(digests: List<Digest>, encodedCertificates: List<ByteArray>) : this(
        digests,
        encodedCertificates,
        DataToSignProto
            .newBuilder()
            .addAllDigests(digests.map { it.protobufRepresentation })
            .addAllCertificates(encodedCertificates.map { ByteString.copyFrom(it) })
            .build()
    )

    fun toByteArray() = protobufedContent.toByteArray()
}

class SignatureData private constructor(
    val algorithmId: Int, val signatureBytes: ByteArray, val protobufedContent: SignatureDataProto
) {
    constructor(protobufedContent: SignatureDataProto) : this(
        protobufedContent.algorithmId,
        protobufedContent.signatureBytes.toByteArray(),
        protobufedContent
    )

    constructor(algorithmId: Int, signatureBytes: ByteArray) : this(
        algorithmId,
        signatureBytes,
        SignatureDataProto
            .newBuilder()
            .setAlgorithmId(algorithmId)
            .setSignatureBytes(ByteString.copyFrom(signatureBytes))
            .build()
    )
}

class Digest private constructor(
    val algorithmId: Int, val digestBytes: ByteArray, val protobufRepresentation: DigestProto
) {
    constructor(protobufedContent: DigestProto) : this(
        protobufedContent.algorithmId,
        protobufedContent.digestBytes.toByteArray(),
        protobufedContent
    )

    constructor(algorithmId: Int, digestBytes: ByteArray) : this(
        algorithmId,
        digestBytes,
        DigestProto
            .newBuilder()
            .setAlgorithmId(algorithmId)
            .setDigestBytes(ByteString.copyFrom(digestBytes))
            .build()
    )
}