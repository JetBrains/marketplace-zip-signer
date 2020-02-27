package org.jetbrains.zip.signer.utils

fun ByteArray.setUnsignedInt32LittleEndian(value: Int, offset: Int) {
    set(offset, (value and 0xff).toByte())
    set(offset + 1, (value shr 8 and 0xff).toByte())
    set(offset + 2, (value shr 16 and 0xff).toByte())
    set(offset + 3, (value shr 24 and 0xff).toByte())
}


@ExperimentalUnsignedTypes
fun ByteArray.toHexString() = asUByteArray().joinToString("") {
    it.toString(16).padStart(2, '0')
}