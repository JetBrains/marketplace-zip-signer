package org.jetbrains.zip.signer.zip

import org.jetbrains.zip.signer.datasource.DataSource

class ZipSections(
    val beforeSigningBlockSection: DataSource,
    val centralDirectorySection: DataSource,
    val endOfCentralDirectorySection: DataSource
) {
    fun toList() = listOf(
        beforeSigningBlockSection, centralDirectorySection, endOfCentralDirectorySection
    )
}