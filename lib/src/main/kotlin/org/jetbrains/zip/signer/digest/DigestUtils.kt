package org.jetbrains.zip.signer.digest

import org.jetbrains.zip.signer.datasource.ByteBufferDataSource
import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.zip.ZipSections
import org.jetbrains.zip.signer.zip.ZipUtils

@ExperimentalUnsignedTypes
internal object DigestUtils {
    fun computeDigest(
        digestAlgorithms: List<ContentDigestAlgorithm>,
        zipSections: ZipSections,
        maximumChunkSize: Int = 1024 * 1024 // 1MB
    ): List<Digest> {
        return computeDigest(
            digestAlgorithms,
            listOf(
                zipSections.beforeSigningBlockSection,
                zipSections.centralDirectorySection,
                ByteBufferDataSource(ZipUtils.getModifiedEocdRecord(zipSections, 0))
            ),
            maximumChunkSize
        )
    }


    private fun computeDigest(
        digestAlgorithms: List<ContentDigestAlgorithm>,
        content: List<DataSource>,
        maximumChunkSize: Int = 1024 * 1024 // 1MB
    ): List<Digest> {
        val chunkIterators = content.map { ChunkIterator(it, maximumChunkSize) }
        val chunkCount = chunkIterators.sumOf { it.chunkCount }
        val digesters = digestAlgorithms.map { ChunkDigester(it, chunkCount) }
        chunkIterators.forEach { chunkIterator ->
            chunkIterator.forEach { chunk ->
                digesters.forEach {
                    it.consume(chunk)
                    chunk.rewind()
                }
            }
        }
        return digesters.map { Digest(it.digestAlgorithm, it.getResult()) }
    }
}