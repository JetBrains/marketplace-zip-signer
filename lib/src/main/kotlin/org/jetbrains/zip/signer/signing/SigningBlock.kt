package org.jetbrains.zip.signer.signing

import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.proto.ZipSignatureSchemeProto
import org.jetbrains.zip.signer.zip.ZipSections
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SigningBlock(val content: ZipSignatureSchemeProto) {
    companion object {
        private const val SIGNATURE_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
        private const val SIGNATURE_BLOCK_MAGIC_LO = 0x20676953204b5040L
        private const val signatureBlockHeaderSize = 8
        private const val signatureBlockFooterSize = 24
        private const val signatureBlockMetadataSize = signatureBlockHeaderSize + signatureBlockFooterSize

        fun findInZip(zipArchive: DataSource, zipSections: ZipSections): SigningBlock? {
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


            val protobufContent = zipArchive.getByteBuffer(
                signingBlockOffset + signatureBlockHeaderSize, totalSize - signatureBlockMetadataSize
            )
            return SigningBlock(ZipSignatureSchemeProto.parseFrom(protobufContent))
        }
    }


    val size = signatureBlockMetadataSize + content.serializedSize

    fun toByteArray(): ByteArray {
        return with(ByteBuffer.allocate(size)) {
            order(ByteOrder.LITTLE_ENDIAN)
            val blockSizeFieldValue = size - 8L
            putLong(blockSizeFieldValue)
            put(content.toByteArray())
            putLong(blockSizeFieldValue)
            putLong(SIGNATURE_BLOCK_MAGIC_LO)
            putLong(SIGNATURE_BLOCK_MAGIC_HI)
            array()
        }
    }
}
