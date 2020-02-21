package org.jetbrains.zip.signer

import com.android.apksig.util.DataSource
import com.android.apksig.util.DataSources
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signing.generateSignerBlock
import org.jetbrains.zip.signer.zip.ZipUtils
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

@ExperimentalUnsignedTypes
object ZipSigner {
    fun sign(
        inputFile: File,
        outputFile: File,
        signerInfo: SignerInfo
    ) {
        RandomAccessFile(inputFile, "r").use { inputRandomAccessFile ->
            RandomAccessFile(outputFile, "rw").use { outputRandomAccessFile ->
                outputRandomAccessFile.setLength(0)
                sign(
                    inputDataSource = DataSources.asDataSource(inputRandomAccessFile),
                    outputFileChannel = outputRandomAccessFile.channel,
                    signerInfo = signerInfo
                )
            }
        }
    }

    private fun sign(
        inputDataSource: DataSource,
        outputFileChannel: FileChannel,
        signerInfo: SignerInfo
    ) {
        val inputZipSections = org.jetbrains.zip.signer.zip.ZipUtils.findZipSections(inputDataSource)
        val inputSigningBlock = ZipMetadata.findInZip(inputDataSource, inputZipSections)

        val algorithms = signerInfo.suggestedSignatureAlgorithms

        val contentDigests = DigestUtils.computeDigest(
            algorithms.map { it.contentDigestAlgorithm },
            listOf(
                inputDataSource.slice(0, inputZipSections.zipCentralDirectoryOffset.toLong()),
                inputDataSource.slice(
                    inputZipSections.zipCentralDirectoryOffset.toLong(),
                    inputZipSections.zipCentralDirectorySizeBytes.toLong()
                ),
                inputDataSource.slice(
                    (inputZipSections.zipCentralDirectoryOffset + inputZipSections.zipCentralDirectorySizeBytes).toLong(),
                    inputDataSource.size() - (inputZipSections.zipCentralDirectoryOffset + inputZipSections.zipCentralDirectorySizeBytes).toLong()
                )
            )
        )
        val signerBlocks = listOf(
            generateSignerBlock(
                signerInfo.certificates, signerInfo.privateKey, algorithms, contentDigests
            )
        )

        val signingBlock = ZipMetadata.fromSignerBlocks(signerBlocks)

        val eocdOffset = inputZipSections.zipCentralDirectoryOffset + inputZipSections.zipCentralDirectorySizeBytes
        val outputEocdRecord = inputDataSource.getByteBuffer(
            eocdOffset.toLong(),
            (inputDataSource.size() - eocdOffset.toLong()).toInt()
        ).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }

        ZipUtils.setZipEocdCentralDirectoryOffset(
            outputEocdRecord,
            (inputZipSections.zipCentralDirectoryOffset.toLong() + signingBlock.size).toUInt()
        )

        inputDataSource.feed(0, inputZipSections.zipCentralDirectoryOffset.toLong(), outputFileChannel)
        outputFileChannel.write(ByteBuffer.wrap(signingBlock.toByteArray()))
        inputDataSource.feed(
            inputZipSections.zipCentralDirectoryOffset.toLong(),
            inputZipSections.zipCentralDirectorySizeBytes.toLong(),
            outputFileChannel
        )
        outputFileChannel.write(outputEocdRecord)
    }
}