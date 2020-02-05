package org.jetbrains.zip.signer.signing

import com.android.apksig.util.DataSource
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

class ChunkIterator(
    private val dataSource: DataSource,
    private val chunkSize: Long = 1024 * 1024
) : Iterator<DataSource> {
    val chunkCount: Long
    private val nextIndex = AtomicInteger(0)

    init {
        chunkCount = getChunkCount(dataSource.size(), chunkSize)
        if (chunkCount > Int.MAX_VALUE) {
            throw RuntimeException(
                String.format("Number of chunks in dataSource is greater than max int.")
            )
        }
    }

    private fun getChunkCount(inputSize: Long, chunkSize: Long): Long {
        return (inputSize + chunkSize - 1) / chunkSize
    }

    override fun hasNext() = nextIndex.get() < chunkCount

    override fun next(): DataSource {
        val index = nextIndex.getAndIncrement()
        if (index < 0 || index >= chunkCount) {
            throw NoSuchElementException()
        }

        val remainingSize = (dataSource.size() - index * chunkSize).coerceAtMost(chunkSize)
        return dataSource.slice(index * chunkSize, remainingSize)
    }
}