package org.jetbrains.zip.signer

import com.android.apksig.internal.zip.CentralDirectoryRecord
import com.android.apksig.internal.zip.ZipUtils
import com.android.apksig.util.DataSink
import com.android.apksig.util.DataSinks
import com.android.apksig.util.DataSource
import com.android.apksig.util.DataSources
import org.jetbrains.zip.signer.algorithm.getSuggestedSignatureAlgorithms
import org.jetbrains.zip.signer.exceptions.PluginFormatException
import org.jetbrains.zip.signer.exceptions.ZipFormatException
import org.jetbrains.zip.signer.signing.ZipMetadata
import org.jetbrains.zip.signer.signing.computeContentDigests
import org.jetbrains.zip.signer.signing.generateSignerBlock
import org.jetbrains.zip.signer.zip.ZipSections
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*

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

        val algorithms = getSuggestedSignatureAlgorithms(signerInfo.certificates.first().publicKey)

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

    private fun getZipCentralDirectory(
        apk: DataSource,
        apkSections: ZipSections
    ): ByteBuffer {
        val cdSizeBytes = apkSections.zipCentralDirectorySizeBytes
        if (cdSizeBytes > Int.MAX_VALUE) {
            throw PluginFormatException("ZIP Central Directory too large: $cdSizeBytes")
        }
        val cdOffset = apkSections.zipCentralDirectoryOffset
        val cd = apk.getByteBuffer(cdOffset, cdSizeBytes.toInt())
        cd.order(ByteOrder.LITTLE_ENDIAN)
        return cd
    }

    private fun parseZipCentralDirectory(
        cd: ByteBuffer,
        apkSections: ZipSections
    ): List<CentralDirectoryRecord> {
        val cdOffset = apkSections.zipCentralDirectoryOffset
        val expectedCdRecordCount = apkSections.zipCentralDirectoryRecordCount
        val cdRecords: MutableList<CentralDirectoryRecord> =
            ArrayList(expectedCdRecordCount)
        val entryNames: MutableSet<String> = HashSet(expectedCdRecordCount)
        for (i in 0 until expectedCdRecordCount) {
            var cdRecord: CentralDirectoryRecord
            val offsetInsideCd = cd.position()
            cdRecord = try {
                CentralDirectoryRecord.getRecord(cd)
            } catch (e: ZipFormatException) {
                throw PluginFormatException(
                    "Malformed ZIP Central Directory record #" + (i + 1)
                            + " at file offset " + (cdOffset + offsetInsideCd),
                    e
                )
            }
            val entryName = cdRecord.name
            if (!entryNames.add(entryName)) {
                throw PluginFormatException(
                    "Multiple ZIP entries with the same name: $entryName"
                )
            }
            cdRecords.add(cdRecord)
        }
        if (cd.hasRemaining()) {
            throw PluginFormatException(
                "Unused space at the end of ZIP Central Directory: " + cd.remaining()
                        + " bytes starting at file offset " + (cdOffset + cd.position())
            )
        }
        return cdRecords
    }
}