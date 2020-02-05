package org.jetbrains.zip.signer.utils

@ExperimentalUnsignedTypes
fun ByteArray.setUnsignedInt32LittleEndian(value: UInt, offset: Int) {
    set(offset, (value and 0xffu).toByte())
    set(offset + 1, (value shr 8 and 0xffu).toByte())
    set(offset + 2, (value shr 16 and 0xffu).toByte())
    set(offset + 3, (value shr 24 and 0xffu).toByte())
}