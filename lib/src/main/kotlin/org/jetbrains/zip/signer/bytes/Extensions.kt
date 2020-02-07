package org.jetbrains.zip.signer.bytes

import java.nio.ByteBuffer

fun ByteBuffer.getLengthPrefixedArray(): ByteArray {
    val data = ByteArray(int)
    get(data)
    return data
}