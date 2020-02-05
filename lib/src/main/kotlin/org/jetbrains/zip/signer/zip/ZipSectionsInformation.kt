package org.jetbrains.zip.signer.zip

class ZipSectionsInformation(
    val centralDirectoryOffset: Long,
    val centralDirectorySizeBytes: Long,
    val endOfCentralDirectoryOffset: Long,
    val endOfCentralDirectorySizeBytes: Int
)