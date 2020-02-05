package org.jetbrains.zip.signer.zip

import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.exceptions.ZipFormatException
import java.nio.ByteOrder

object ZipUtils {
    fun findZipSections(apk: DataSource): ZipSections {
        val (eocdBuf, eocdOffset) = ZipUtils.findZipEndOfCentralDirectoryRecord(apk)
            ?: throw ZipFormatException("ZIP End of Central Directory record not found")
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN)
        val cdStartOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocdBuf)
        if (cdStartOffset > eocdOffset) {
            throw ZipFormatException(
                "ZIP Central Directory start offset out of range: " + cdStartOffset
                        + ". ZIP End of Central Directory offset: " + eocdOffset
            )
        }
        val cdSizeBytes = ZipUtils.getZipEocdCentralDirectorySizeBytes(eocdBuf)
        val cdEndOffset = cdStartOffset + cdSizeBytes
        if (cdEndOffset > eocdOffset) {
            throw ZipFormatException(
                "ZIP Central Directory overlaps with End of Central Directory"
                        + ". CD end: " + cdEndOffset
                        + ", EoCD start: " + eocdOffset
            )
        }
        val cdRecordCount =
            ZipUtils.getZipEocdCentralDirectoryTotalRecordCount(eocdBuf)
        return ZipSections(
            cdStartOffset,
            cdSizeBytes,
            cdRecordCount,
            eocdOffset,
            eocdBuf
        )
    }
}