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

    fun findZipSections(apk: DataSource): ZipSections {
        val (eocdBuf, eocdOffset) = findZipEndOfCentralDirectoryRecord(apk)
            ?: throw ZipException("ZIP End of Central Directory record not found")
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN)
        val cdStartOffset = getZipEocdCentralDirectoryOffset(eocdBuf)
        if (cdStartOffset.toLong() > eocdOffset) {
            throw ZipException(
                "ZIP Central Directory start offset out of range: " + cdStartOffset
                        + ". ZIP End of Central Directory offset: " + eocdOffset
            )
        }
        val cdSizeBytes = getZipEocdCentralDirectorySizeBytes(eocdBuf)
        val cdEndOffset = cdStartOffset + cdSizeBytes
        if (cdEndOffset.toLong() > eocdOffset) {
            throw ZipException(
                "ZIP Central Directory overlaps with End of Central Directory"
                        + ". CD end: " + cdEndOffset
                        + ", EoCD start: " + eocdOffset
            )
        }
        return ZipSections(
            cdStartOffset,
            cdSizeBytes,
            eocdOffset,
            eocdBuf
        )
    }

    private fun findZipEndOfCentralDirectoryRecord(zip: DataSource): Pair<ByteBuffer, Long>? {
        val fileSize = zip.size()
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) return null
        val result = findZipEndOfCentralDirectoryRecord(zip, 0u)
        return result ?: findZipEndOfCentralDirectoryRecord(
            zip,
            UShort.MAX_VALUE
        )
    }


    private fun findZipEndOfCentralDirectoryRecord(
        zip: DataSource, maxCommentSize: UShort
    ): Pair<ByteBuffer, Long>? {
        val fileSize = zip.size()
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) return null

        val maxEocdSize = ZIP_EOCD_REC_MIN_SIZE + maxCommentSize.toInt().coerceAtMost(
            fileSize.toInt() - ZIP_EOCD_REC_MIN_SIZE
        )
        val bufOffsetInFile = fileSize - maxEocdSize
        val buf = zip.getByteBuffer(bufOffsetInFile, maxEocdSize)
        buf.order(ByteOrder.LITTLE_ENDIAN)
        val eocdOffsetInBuf = findZipEndOfCentralDirectoryRecord(buf)
        if (eocdOffsetInBuf == -1) { // No EoCD record found in the buffer
            return null
        }
        // EoCD found
        buf.position(eocdOffsetInBuf)
        val eocd = buf.slice()
        eocd.order(ByteOrder.LITTLE_ENDIAN)
        return eocd to bufOffsetInFile + eocdOffsetInBuf
    }

    private fun findZipEndOfCentralDirectoryRecord(zipContents: ByteBuffer): Int {
        assert(zipContents.isLittleEndian())
        val archiveSize = zipContents.capacity()
        if (archiveSize < ZIP_EOCD_REC_MIN_SIZE) {
            return -1
        }
        val maxCommentLength = (archiveSize - ZIP_EOCD_REC_MIN_SIZE).coerceAtMost(UShort.MAX_VALUE.toInt()).toUShort()
        val eocdWithEmptyCommentStartPosition = archiveSize - ZIP_EOCD_REC_MIN_SIZE
        for (expectedCommentLength in 0u..maxCommentLength.toUInt()) {
            val eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength.toInt()
            if (zipContents.getInt(eocdStartPos) == ZIP_EOCD_REC_SIG) {
                val actualCommentLength = zipContents.getUnsignedShort(
                    eocdStartPos + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET
                )
                if (actualCommentLength == expectedCommentLength.toUShort()) {
                    return eocdStartPos
                }
            }
        }
        return -1
    }

    private fun getZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer): UInt {
        assert(zipEndOfCentralDirectory.isLittleEndian())
        return zipEndOfCentralDirectory.getUnsignedInt(
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET
        )
    }

    fun setZipEocdCentralDirectoryOffset(
        zipEndOfCentralDirectory: ByteBuffer, offset: UInt
    ) {
        assert(zipEndOfCentralDirectory.isLittleEndian())
        zipEndOfCentralDirectory.setUnsignedInt(
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET, offset
        )
    }

    fun getZipEocdCentralDirectorySizeBytes(zipEndOfCentralDirectory: ByteBuffer): UInt {
        assert(zipEndOfCentralDirectory.isLittleEndian())
        return zipEndOfCentralDirectory.getUnsignedInt(
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET
        )
    }

}