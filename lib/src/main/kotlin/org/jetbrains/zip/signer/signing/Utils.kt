package org.jetbrains.zip.signer.signing

fun setUnsignedInt32LittleEndian(value: Int, result: ByteArray, offset: Int) {
    result[offset] = (value and 0xff).toByte()
    result[offset + 1] = (value shr 8 and 0xff).toByte()
    result[offset + 2] = (value shr 16 and 0xff).toByte()
    result[offset + 3] = (value shr 24 and 0xff).toByte()
}