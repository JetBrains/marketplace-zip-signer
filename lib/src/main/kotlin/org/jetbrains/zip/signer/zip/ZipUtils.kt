package org.jetbrains.zip.signer.zip

import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.utils.getUnsignedInt
import org.jetbrains.zip.signer.utils.getUnsignedShort
import org.jetbrains.zip.signer.utils.isLittleEndian
import org.jetbrains.zip.signer.utils.setUnsignedInt
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipException

@ExperimentalUnsignedTypes
internal object ZipUtils {
    private const val ZIP_EOCD_REC_MIN_SIZE = 22
    private const val ZIP_EOCD_REC_SIG = 0x06054b50

    private const val ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
    private const val ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
    private const val ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20

    fun findZipSectionsInformation(zip: DataSource): ZipSectionsInformation {
        val (eocdOffset, eocd) = findEocdInBuffer(zip)
            ?: throw ZipException("ZIP End of Central Directory record not found")
        val centralDirectoryEndOffset = eocd.centralDirectoryOffset.toLong() + eocd.centralDirectorySize.toLong()

        if (eocd.centralDirectoryOffset.toLong() > eocdOffset) {
            throw ZipException("ZIP Central Directory start offset out of range")
        }
        if (centralDirectoryEndOffset > eocdOffset) {
            throw ZipException("ZIP Central Directory overlaps with End of Central Directory")
        }

        return ZipSectionsInformation(
            centralDirectoryOffset = eocd.centralDirectoryOffset.toLong(),
            centralDirectorySizeBytes = eocd.centralDirectorySize.toLong(),
            endOfCentralDirectoryOffset = eocdOffset,
            endOfCentralDirectorySizeBytes = (zip.size() - eocdOffset).toInt()
        )
    }

    internal fun findZipSections(
        zip: DataSource,
        zipSectionsInformation: ZipSectionsInformation,
        zipMetadata: ZipMetadata?
    ) = ZipSections(
        zip.slice(0, zipSectionsInformation.centralDirectoryOffset - (zipMetadata?.size?.toLong() ?: 0)),
        zip.slice(zipSectionsInformation.centralDirectoryOffset, zipSectionsInformation.centralDirectorySizeBytes),
        zip.slice(
            zipSectionsInformation.endOfCentralDirectoryOffset,
            zipSectionsInformation.endOfCentralDirectorySizeBytes.toLong()
        )
    )

    internal fun setZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer, offset: UInt) {
        require(zipEndOfCentralDirectory.isLittleEndian())
        zipEndOfCentralDirectory.setUnsignedInt(
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET,
            offset
        )
    }

    /**
     * We are guessing that it's a zip archive without comment to read only 22 bytes of data.
     * If we are wrong we are iterating over archive content from the end to the beginning to find EOCD
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
        require(zipContents.isLittleEndian())
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

    private fun parseEOCD(eocdSection: ByteBuffer): ZipEocdData? {
        with(eocdSection) {
            require(isLittleEndian())
            if (getInt(position()) != ZIP_EOCD_REC_SIG) return null
            return ZipEocdData(
                getUnsignedInt(position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET),
                getUnsignedInt(position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET),
                getUnsignedShort(position() + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET)
            )
        }
    }

    private data class ZipEocdData(
        val centralDirectoryOffset: UInt,
        val centralDirectorySize: UInt,
        val commentLength: UShort
    )
}