package org.jetbrains.zip.signer.utils

import java.nio.ByteBuffer
import java.nio.ByteOrder

fun ByteBuffer.getLengthPrefixedArray(): ByteArray {
    val data = ByteArray(int)
    get(data)
    return data
}

fun ByteBuffer.isLittleEndian() = order() == ByteOrder.LITTLE_ENDIAN

@ExperimentalUnsignedTypes
fun ByteBuffer.getUnsignedInt(offset: Int) = this.getInt(offset).toUInt()

@ExperimentalUnsignedTypes
fun ByteBuffer.setUnsignedInt(offset: Int, value: UInt) = this.putInt(offset, value.toInt())

@ExperimentalUnsignedTypes
fun ByteBuffer.getUnsignedShort(offset: Int) = this.getShort(offset).toUShort()