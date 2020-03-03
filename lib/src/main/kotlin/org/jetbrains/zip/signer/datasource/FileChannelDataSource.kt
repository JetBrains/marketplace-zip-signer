/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jetbrains.zip.signer.datasource

import java.io.IOException
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.WritableByteChannel

class FileChannelDataSource(
    private val channel: FileChannel,
    private val offset: Long = 0,
    val size: Long? = null
) : DataSource {
    companion object {
        private const val MAX_READ_CHUNK_SIZE = 1024 * 1024
        private fun checkChunkValid(offset: Long, size: Long, sourceSize: Long) {
            val endOffset = offset + size
            if (offset < 0) throw IndexOutOfBoundsException("offset: $offset")
            if (size < 0) throw IndexOutOfBoundsException("size: $size")
            if (offset > sourceSize) throw IndexOutOfBoundsException("offset ($offset) > source size ($sourceSize)")
            if (endOffset < offset) throw IndexOutOfBoundsException("offset ($offset) + size ($size) overflow")
            if (endOffset > sourceSize) throw IndexOutOfBoundsException("offset ($offset) + size ($size) > source size ($sourceSize)")
        }
    }

    init {
        if (offset < 0) throw IndexOutOfBoundsException("offset: $size")
        if (size != null && size < 0) throw IndexOutOfBoundsException("size: $size")
    }

    override fun size() = size ?: channel.size()

    override fun slice(offset: Long, size: Long): FileChannelDataSource {
        val sourceSize = size()
        checkChunkValid(offset, size, sourceSize)
        return if (offset == 0L && size == sourceSize) this
        else FileChannelDataSource(channel, this.offset + offset, size)
    }

    override fun feed(writableByteChannel: WritableByteChannel, offset: Long, size: Long) {
        val sourceSize = size()
        checkChunkValid(offset, size, sourceSize)
        if (size == 0L) return
        var chunkOffsetInFile = this.offset + offset
        var remaining = size
        val buf = ByteBuffer.allocateDirect(remaining.toInt().coerceAtMost(MAX_READ_CHUNK_SIZE))
        while (remaining > 0) {
            val chunkSize = remaining.coerceAtMost(buf.capacity().toLong()).toInt()
            var chunkRemaining = chunkSize
            buf.limit(chunkSize)
            channel.position(chunkOffsetInFile)
            while (chunkRemaining > 0) {
                val read = channel.read(buf)
                if (read < 0) throw IOException("Unexpected EOF encountered")
                chunkRemaining -= read
            }
            buf.flip()
            writableByteChannel.write(buf)
            buf.clear()
            chunkOffsetInFile += chunkSize.toLong()
            remaining -= chunkSize.toLong()
        }
    }

    override fun copyTo(offset: Long, size: Int, dest: ByteBuffer) {
        val sourceSize = size()
        checkChunkValid(offset, size.toLong(), sourceSize)
        if (size == 0) return
        if (size > dest.remaining()) throw BufferOverflowException()
        var offsetInFile = this.offset + offset
        var remaining = size
        val prevLimit = dest.limit()
        try {
            dest.limit(dest.position() + size)
            while (remaining > 0) {
                channel.position(offsetInFile)
                val chunkSize: Int = channel.read(dest)
                offsetInFile += chunkSize.toLong()
                remaining -= chunkSize
            }
        } finally {
            dest.limit(prevLimit)
        }
    }

    override fun getByteBuffer(offset: Long, size: Int): ByteBuffer {
        if (size < 0) throw IndexOutOfBoundsException("size: $size")
        val result = ByteBuffer.allocate(size)
        copyTo(offset, size, result)
        result.flip()
        return result
    }
}