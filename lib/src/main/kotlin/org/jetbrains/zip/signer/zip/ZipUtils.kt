package org.jetbrains.zip.signer.zip

import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.utils.getUnsignedInt
import org.jetbrains.zip.signer.utils.getUnsignedShort
import org.jetbrains.zip.signer.utils.isLittleEndian
import org.jetbrains.zip.signer.utils.setUnsignedInt
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipException

@ExperimentalUnsignedTypes
object ZipUtils {
    private const val ZIP_EOCD_REC_MIN_SIZE = 22
    private const val ZIP_EOCD_REC_SIG = 0x06054b50

    private const val ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
    private const val ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
    private const val ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20

    fun findZipSections(zip: DataSource): ZipSections {
        val (eocdOffset, eocd) = findEocdInBuffer(zip)
            ?: throw ZipException("ZIP End of Central Directory record not found")
        val centralDirectoryEndOffset = eocd.centralDirectoryOffset.toLong() + eocd.centralDirectorySize.toLong()

        if (eocd.centralDirectoryOffset.toLong() > eocdOffset) {
            throw ZipException("ZIP Central Directory start offset out of range")
        }
        if (centralDirectoryEndOffset > eocdOffset) {
            throw ZipException("ZIP Central Directory overlaps with End of Central Directory")
        }

        return ZipSections(
            eocd.centralDirectoryOffset.toLong(),
            eocd.centralDirectorySize.toLong(),
            eocdOffset,
            zip.size() - eocdOffset
        )
    }

    /**
     * We are guessing that it's a zip archive without comment to read only 22 bytes of data.
     * If we are wrong we are parsing iterating over archive content from the end to the beginning to find EOCD
     */
    private fun findEocdInBuffer(zip: DataSource) =
        findEocdInBuffer(zip, 0u) ?: findEocdInBuffer(zip, UShort.MAX_VALUE)


    private fun findEocdInBuffer(zip: DataSource, maxCommentSize: UShort): Pair<Long, ZipEocdData>? {
        val fileSize = zip.size()
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) return null
        val maxEocdSize = ZIP_EOCD_REC_MIN_SIZE + maxCommentSize.toInt().coerceAtMost(
            fileSize.toInt() - ZIP_EOCD_REC_MIN_SIZE
        )
        val bufOffsetInFile = fileSize - maxEocdSize
        val buf = zip.getByteBuffer(bufOffsetInFile, maxEocdSize).apply { order(ByteOrder.LITTLE_ENDIAN) }
        val (eocdOffsetInBuffer, eocd) = findEocdInBuffer(buf) ?: return null
        return bufOffsetInFile + eocdOffsetInBuffer to eocd
    }

    private fun findEocdInBuffer(zipContents: ByteBuffer): Pair<Int, ZipEocdData>? {
        assert(zipContents.isLittleEndian())
        val eocdWithEmptyCommentStartPosition = zipContents.capacity() - ZIP_EOCD_REC_MIN_SIZE
        if (eocdWithEmptyCommentStartPosition < 0) return null
        for (possibleCommentLength in 0..eocdWithEmptyCommentStartPosition.coerceAtMost(UShort.MAX_VALUE.toInt())) {
            zipContents.position(eocdWithEmptyCommentStartPosition - possibleCommentLength)
            val zipEocd = parseEOCD(zipContents) ?: continue
            if (zipEocd.commentLength.toInt() != possibleCommentLength) continue
            return zipContents.position() to zipEocd
        }
        return null
    }

    fun setZipEocdCentralDirectoryOffset(
        zipEndOfCentralDirectory: ByteBuffer, offset: UInt
    ) {
        assert(zipEndOfCentralDirectory.isLittleEndian())
        zipEndOfCentralDirectory.setUnsignedInt(
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET, offset
        )
    }

    private fun parseEOCD(eocdSection: ByteBuffer): ZipEocdData? {
        with(eocdSection) {
            assert(isLittleEndian())
            if (getInt(position()) != ZIP_EOCD_REC_SIG) return null
            return ZipEocdData(
                getUnsignedInt(position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET),
                getUnsignedInt(position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET),
                getUnsignedShort(position() + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET)
            )
        }
    }

    data class ZipEocdData(
        val centralDirectoryOffset: UInt,
        val centralDirectorySize: UInt,
        val commentLength: UShort
    )
}