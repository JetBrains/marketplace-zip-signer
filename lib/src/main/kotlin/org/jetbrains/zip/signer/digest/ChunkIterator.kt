package org.jetbrains.zip.signer.digest

import org.jetbrains.zip.signer.datasource.DataSource
import java.nio.ByteBuffer
import java.util.*

internal class ChunkIterator(
    private val dataSource: DataSource,
    private val maximumChunkSize: Int = 1024 * 1024
) : Iterator<ByteBuffer> {
    val chunkCount = getChunkCount(dataSource.size(), maximumChunkSize)
    private var index = 0

    override fun hasNext() = index < chunkCount

    override fun next(): ByteBuffer {
        if (index < 0 || index >= chunkCount) throw NoSuchElementException()
        val chunkSize = (dataSource.size() - index * maximumChunkSize).coerceAtMost(maximumChunkSize.toLong()).toInt()
        val chunk = dataSource.getByteBuffer(index * maximumChunkSize.toLong(), chunkSize)
        index += 1
        return chunk
    }

    private fun getChunkCount(inputSize: Long, chunkSize: Int): Int {
        val chunkCountLong = (inputSize + chunkSize - 1) / chunkSize
        require(chunkCountLong < Int.MAX_VALUE) {
            "Number of chunks in dataSource is greater than max int."
        }
        return chunkCountLong.toInt()
    }
}