package org.jetbrains.zip.signer.zip

import java.nio.ByteBuffer

@ExperimentalUnsignedTypes
class ZipSections(
    /**
     * Returns the start offset of the ZIP Central Directory. This value is taken from the
     * ZIP End of Central Directory record.
     */
    val zipCentralDirectoryOffset: UInt,
    /**
     * Returns the size (in bytes) of the ZIP Central Directory. This value is taken from the
     * ZIP End of Central Directory record.
     */
    val zipCentralDirectorySizeBytes: UInt,
    /**
     * Returns the start offset of the ZIP End of Central Directory record. The record extends
     * until the very end of the APK.
     */
    val zipEndOfCentralDirectoryOffset: Long,
    /**
     * Returns the contents of the ZIP End of Central Directory.
     */
    val zipEndOfCentralDirectory: ByteBuffer
)