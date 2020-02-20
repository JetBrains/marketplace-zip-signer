package org.jetbrains.zip.signer.bytes

import java.nio.ByteBuffer

fun ByteBuffer.getLengthPrefixedArray(): ByteArray {
    val data = ByteArray(int)
    get(data)
    return data
}

/**
 * Creates a new byte buffer whose content is a next n bytes of
 * this buffer's content. Also updates position of current buffer
 * @param size size of bytes to get
 * @return byte buffer that wraps next size bytes
 */
fun ByteBuffer.getByteBuffer(size: Int): ByteBuffer {
    require(size >= 0) { "Size can't be negative" }
    require(size <= remaining()) { "Requested size is more that remaining." }
    val originalLimit = limit()
    return try {
        limit(position() + size)
        val result = slice()
        result.order(order())
        result
    } finally {
        position(position() + size)
        limit(originalLimit)
    }
}

fun ByteBuffer.sliceFromTo(start: Int, end: Int): ByteBuffer {
    require(start >= 0) { "start: $start" }
    require(end >= start) { "end < start: $end < $start" }
    require(end <= capacity()) { "end > capacity: $end > ${capacity()}" }
    val originalLimit = limit()
    val originalPosition = position()
    return try {
        position(0)
        limit(end)
        position(start)
        val result = slice()
        result.order(order())
        result
    } finally {
        position(0)
        limit(originalLimit)
        position(originalPosition)
    }
}