package org.jetbrains.zip.signer.digest

import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.utils.setUnsignedInt32LittleEndian
import java.nio.ByteBuffer
import java.security.MessageDigest

@ExperimentalUnsignedTypes
internal class ChunkDigester(val digestAlgorithm: ContentDigestAlgorithm, private val chunkCount: Int) {
    private val chunkPrefix: Byte = 0x5a
    private val messageDigest = MessageDigest.getInstance(digestAlgorithm.jcaMessageDigestAlgorithm)
    private val digest = ByteArray(5 + chunkCount * digestAlgorithm.chunkDigestOutputSizeBytes).apply {
        set(0, chunkPrefix)
        setUnsignedInt32LittleEndian(chunkCount.toUInt(), 1)
    }
    private var position = 0

    fun consume(chunk: ByteBuffer) {
        if (position >= chunkCount) error("Too many chunks provided")

        val chunkPrefix = ByteArray(5).apply {
            set(0, chunkPrefix)
            setUnsignedInt32LittleEndian(chunk.remaining().toUInt(), 1)
        }
        messageDigest.update(chunkPrefix)
        messageDigest.update(chunk)
        val bytesWritten = messageDigest.digest(
            digest,
            5 + position * digestAlgorithm.chunkDigestOutputSizeBytes,
            digestAlgorithm.chunkDigestOutputSizeBytes
        )

        require(bytesWritten == digestAlgorithm.chunkDigestOutputSizeBytes) {
            "Digest algorithm output has an unexpected size"
        }

        position += 1
    }

    fun getResult(): ByteArray {
        require(position == chunkCount) {
            "Not all chunks were processed"
        }
        return digest
    }


}