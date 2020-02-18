package org.jetbrains.zip.signer.zip

import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSource
import java.nio.ByteOrder
import java.util.zip.ZipException

object ZipUtils {
    fun findZipSections(apk: DataSource): ZipSections {
        val (eocdBuf, eocdOffset) = ZipUtils.findZipEndOfCentralDirectoryRecord(apk)
            ?: throw ZipException("ZIP End of Central Directory record not found")
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN)
        val cdStartOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocdBuf)
        if (cdStartOffset > eocdOffset) {
            throw ZipException(
                "ZIP Central Directory start offset out of range: " + cdStartOffset
                        + ". ZIP End of Central Directory offset: " + eocdOffset
            )
        }
        val cdSizeBytes = ZipUtils.getZipEocdCentralDirectorySizeBytes(eocdBuf)
        val cdEndOffset = cdStartOffset + cdSizeBytes
        if (cdEndOffset > eocdOffset) {
            throw ZipException(
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