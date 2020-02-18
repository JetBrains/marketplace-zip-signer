package org.jetbrains.zip.signer.bytes

import java.nio.ByteBuffer

fun ByteBuffer.getLengthPrefixedArray(): ByteArray {
    val data = ByteArray(int)
    get(data)
    return data
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