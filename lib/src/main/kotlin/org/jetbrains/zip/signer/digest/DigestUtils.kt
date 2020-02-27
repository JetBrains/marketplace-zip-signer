package org.jetbrains.zip.signer.digest

import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.Digest

object DigestUtils {
    fun computeDigest(
        digestAlgorithms: List<ContentDigestAlgorithm>,
        content: List<DataSource>,
        maximumChunkSize: Int = 1024 * 1024 // 1MB
    ): List<Digest> {
        val chunkIterators = content.map { ChunkIterator(it, maximumChunkSize) }
        val chunkCount = chunkIterators.sumBy { it.chunkCount }
        val digesters = digestAlgorithms.map { ChunkDigester(it, chunkCount) }
        chunkIterators.forEach { chunkIterator ->
            chunkIterator.forEach { chunk ->
                digesters.forEach { it.consume(chunk) }
            }
        }
        return digesters.map { Digest(it.digestAlgorithm, it.getResult()) }
    }
}