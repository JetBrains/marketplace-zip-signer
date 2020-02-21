package org.jetbrains.zip.signer.zip

class ZipSections(
    val centralDirectoryOffset: Long,
    val centralDirectorySizeBytes: Long,
    val endOfCentralDirectoryOffset: Long,
    val endOfCentralDirectorySizeBytes: Long
)