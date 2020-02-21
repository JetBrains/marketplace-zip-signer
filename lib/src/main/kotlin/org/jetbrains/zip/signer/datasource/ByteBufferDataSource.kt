package org.jetbrains.zip.signer.datasource

import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

class ByteBufferDataSource(private val buffer: ByteBuffer) :
    DataSource {
    private val size: Int = buffer.remaining()

    override fun size() = size.toLong()

    override fun getByteBuffer(offset: Long, size: Int): ByteBuffer {
        checkChunkValid(offset, size.toLong())
        val chunkPosition = offset.toInt()
        val chunkLimit = chunkPosition + size

        buffer.position(0)
        buffer.limit(chunkLimit)
        buffer.position(chunkPosition)
        return buffer.slice()
    }

    override fun copyTo(offset: Long, size: Int, dest: ByteBuffer) {
        dest.put(getByteBuffer(offset, size))
    }

    override fun feed(offset: Long, size: Long, writableByteChannel: WritableByteChannel) {
        if (size < 0 || size > size) {
            throw IndexOutOfBoundsException("size: $size, source size: $size")
        }
        writableByteChannel.write(getByteBuffer(offset, size.toInt()))
    }

    override fun slice(offset: Long, size: Long): ByteBufferDataSource {
        if (offset == 0L && size == size) {
            return this
        }
        if (size < 0 || size > size) {
            throw IndexOutOfBoundsException("size: $size, source size: $size")
        }
        return ByteBufferDataSource(
            getByteBuffer(offset, size.toInt())
        )
    }

    private fun checkChunkValid(offset: Long, size: Long) {
        val endOffset = offset + size
        if (offset < 0) throw IndexOutOfBoundsException("offset: $offset")
        if (size < 0) throw IndexOutOfBoundsException("size: $size")
        if (offset > size) throw IndexOutOfBoundsException("offset ($offset) > source size ($size)")
        if (endOffset < offset) throw IndexOutOfBoundsException("offset ($offset) + size ($size) overflow")
        if (endOffset > size) throw IndexOutOfBoundsException("offset ($offset) + size ($size) > source size ($size)")
    }
}