package org.jetbrains.zip.signer.signing

import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.zip.ZipSections
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

object SigningBlockUtils {
    private const val SIGNATURE_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
    private const val SIGNATURE_BLOCK_MAGIC_LO = 0x20676953204b5041L
    private const val SIGNATURE_BLOCK_MIN_SIZE = 32

    /**
     * Returns the signing block of the provided zip archive.
     * OFFSET       DATA TYPE  DESCRIPTION
     * @+0  bytes uint64:    size in bytes (excluding this field)
     * @+8  bytes payload
     * @-24 bytes uint64:    size in bytes (same as the one above)
     * @-16 bytes uint128:   magic
     *
     * @throws IOException                   if an I/O error occurs
     */
    fun findZipSigningBlock(
        zipArchive: DataSource,
        zipSections: ZipSections
    ): SigningBlockInfo? {
        val centralDirStartOffset = zipSections.zipCentralDirectoryOffset
        val centralDirEndOffset = centralDirStartOffset + zipSections.zipCentralDirectorySizeBytes
        if (centralDirEndOffset != zipSections.zipEndOfCentralDirectoryOffset) return null
        if (centralDirStartOffset < SIGNATURE_BLOCK_MIN_SIZE) return null

        val footer = zipArchive.getByteBuffer(centralDirStartOffset - 24, 24).apply {
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
        val signatureBlock = zipArchive.getByteBuffer(signingBlockOffset, 8).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }
        val signatureBlockSizeInHeader = signatureBlock.getLong(0)
        if (signatureBlockSizeInHeader != signatureBlockSizeInFooter) return null

        val dataSource = zipArchive.slice(signingBlockOffset, totalSize.toLong())
        val signingBlockContent = dataSource.getByteBuffer(0, dataSource.size().toInt()).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }

        return SigningBlockInfo(signingBlockOffset, signingBlockContent)
    }
}

class SigningBlockInfo(val startOffset: Long, val content: ByteBuffer)
