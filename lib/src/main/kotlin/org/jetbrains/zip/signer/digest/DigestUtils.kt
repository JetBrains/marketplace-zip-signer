package org.jetbrains.zip.signer.digest

import com.android.apksig.util.DataSource
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm

object DigestUtils {
    fun computeDigest(
        digestAlgorithms: List<ContentDigestAlgorithm>,
        content: List<DataSource>,
        maximumChunkSize: Int = 1024 * 1024 // 1MB
    ): Map<ContentDigestAlgorithm, ByteArray> {
        val chunkIterators = content.map {
            ChunkIterator(
                it,
                maximumChunkSize
            )
        }
        val chunkCount = chunkIterators.sumBy { it.chunkCount }
        val digesters = digestAlgorithms.map {
            ChunkDigester(
                it,
                chunkCount
            )
        }
        chunkIterators.forEach { chunkIterator ->
            chunkIterator.forEach { chunk ->
                digesters.forEach { it.consume(chunk) }
            }
        }
        return digesters.associate { it.digestAlgorithm to it.getResult() }
    }
}