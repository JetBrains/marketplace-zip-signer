package org.jetbrains.zip.signer.metadata

import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.proto.ZipMetadataProto
import org.jetbrains.zip.signer.proto.ZipSignatureBlockProto
import org.jetbrains.zip.signer.zip.ZipSectionsInformation
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ZipMetadata private constructor(
    val digests: List<Digest>,
    val signers: List<SignerBlock>,
    private val protobufRepresentation: ZipMetadataProto
) {
    @ExperimentalUnsignedTypes
    companion object {
        private const val SIGNATURE_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
        private const val SIGNATURE_BLOCK_MAGIC_LO = 0x20676953204b5040L
        private const val signatureBlockHeaderSize = 8
        private const val signatureBlockFooterSize = 24
        private const val signatureBlockMetadataSize = signatureBlockHeaderSize + signatureBlockFooterSize

        fun findInZip(zipArchive: DataSource, zipSectionsInformation: ZipSectionsInformation): ZipMetadata? {
            val centralDirStartOffset = zipSectionsInformation.centralDirectoryOffset
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
                    signingBlockOffset + signatureBlockHeaderSize,
                    totalSize - signatureBlockMetadataSize
                )
            )
            assert(protobufContent.signatureSchemeVersion == 1)

            return ZipMetadata(
                protobufContent.content.digestsList.map { Digest(it) },
                protobufContent.content.signersList.map { SignerBlock(it) },
                protobufContent
            )
        }
    }

    constructor(digests: List<Digest>, signers: List<SignerBlock>) : this(
        digests,
        signers,
        ZipMetadataProto
            .newBuilder()
            .setSignatureSchemeVersion(1)
            .setContent(
                ZipSignatureBlockProto
                    .newBuilder()
                    .addAllDigests(digests.map { it.protobufRepresentation })
                    .addAllSigners(signers.map { it.protobufRepresentation })
                    .build()
            )
            .build()
    )

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

