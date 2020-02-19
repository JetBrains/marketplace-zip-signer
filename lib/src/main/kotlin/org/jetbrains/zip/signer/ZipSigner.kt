package org.jetbrains.zip.signer

import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSink
import com.android.apksig.util.DataSinks
import com.android.apksig.util.DataSource
import com.android.apksig.util.DataSources
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signing.computeContentDigests
import org.jetbrains.zip.signer.signing.generateSignerBlock
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

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
                    outputDataSink = DataSinks.asDataSink(outputRandomAccessFile),
                    signerInfo = signerInfo
                )
            }
        }
    }

    private fun sign(
        inputDataSource: DataSource,
        outputDataSink: DataSink,
        signerInfo: SignerInfo
    ) {
        val inputZipSections = org.jetbrains.zip.signer.zip.ZipUtils.findZipSections(inputDataSource)
        val inputSigningBlock = ZipMetadata.findInZip(inputDataSource, inputZipSections)

        val algorithms = signerInfo.suggestedSignatureAlgorithms

        val contentDigests = computeContentDigests(
            algorithms.map { it.contentDigestAlgorithm },
            inputDataSource.slice(0, inputZipSections.zipCentralDirectoryOffset),
            inputDataSource.slice(
                inputZipSections.zipCentralDirectoryOffset,
                inputZipSections.zipCentralDirectorySizeBytes
            ),
            inputDataSource.slice(
                inputZipSections.zipCentralDirectoryOffset + inputZipSections.zipCentralDirectorySizeBytes,
                inputDataSource.size() - (inputZipSections.zipCentralDirectoryOffset + inputZipSections.zipCentralDirectorySizeBytes)
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
            eocdOffset,
            (inputDataSource.size() - eocdOffset).toInt()
        ).apply {
            order(ByteOrder.LITTLE_ENDIAN)
        }

        ZipUtils.setZipEocdCentralDirectoryOffset(
            outputEocdRecord,
            inputZipSections.zipCentralDirectoryOffset + signingBlock.size
        )

        outputDataSink.consume(inputDataSource.getByteBuffer(0, inputZipSections.zipCentralDirectoryOffset.toInt()))
        outputDataSink.consume(ByteBuffer.wrap(signingBlock.toByteArray()))
        outputDataSink.consume(
            inputDataSource.getByteBuffer(
                inputZipSections.zipCentralDirectoryOffset, inputZipSections.zipCentralDirectorySizeBytes.toInt()
            )
        )
        outputDataSink.consume(outputEocdRecord)
    }
}