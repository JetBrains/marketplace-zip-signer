package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.datasource.FileChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signer.SignerInfo
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.jetbrains.zip.signer.zip.ZipSections
import org.jetbrains.zip.signer.zip.ZipUtils
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

@ExperimentalUnsignedTypes
object ZipSigner {
    fun sign(inputFile: File, outputFile: File, signerInfo: SignerInfo) {
        RandomAccessFile(inputFile, "r").use { inputRandomAccessFile ->
            RandomAccessFile(outputFile, "rw").use { outputRandomAccessFile ->
                outputRandomAccessFile.setLength(0)
                sign(FileChannelDataSource(inputRandomAccessFile.channel), outputRandomAccessFile.channel, signerInfo)
            }
        }
    }

    private fun sign(inputDataSource: DataSource, outputFileChannel: FileChannel, signerInfo: SignerInfo) {
        val inputZipSectionsInformation = ZipUtils.findZipSectionsInformation(inputDataSource)
        val inputSigningBlock = ZipMetadata.findInZip(inputDataSource, inputZipSectionsInformation)
        val inputZipSections = ZipUtils.findZipSections(inputDataSource, inputZipSectionsInformation, inputSigningBlock)

        val outputDigests = getOutputDigests(inputSigningBlock, inputZipSections, signerInfo)
        val newSignerBlock = generateSignerBlock(
            certificates = signerInfo.certificates,
            privateKey = signerInfo.privateKey,
            signatureAlgorithms = signerInfo.signatureAlgorithms,
            contentDigests = outputDigests
        )
        val outputSignerBlocks = (inputSigningBlock?.signers ?: emptyList()) + newSignerBlock
        val outputMetadata = ZipMetadata(outputDigests, outputSignerBlocks)

        generateSignedZip(inputZipSections, outputMetadata, outputFileChannel)
    }

    private fun getOutputDigests(
        inputSigningBlock: ZipMetadata?,
        inputZipSections: ZipSections,
        signerInfo: SignerInfo
    ) = if (inputSigningBlock != null) {
        ZipVerifier.checkDigests(inputZipSections, inputSigningBlock)
        val missingDigests = DigestUtils.computeDigest(
            signerInfo.requiredDigests - inputSigningBlock.digests.map { it.algorithm },
            inputZipSections.toList()
        )
        inputSigningBlock.digests + missingDigests
    } else {
        DigestUtils.computeDigest(signerInfo.requiredDigests, inputZipSections.toList())
    }

    private fun generateSignedZip(
        inputZipSections: ZipSections,
        outputMetadata: ZipMetadata,
        outputFileChannel: FileChannel
    ) {
        val outputEocdRecord = inputZipSections.endOfCentralDirectorySection
            .getByteBuffer(0, inputZipSections.endOfCentralDirectorySection.size().toInt())
            .apply {
                order(ByteOrder.LITTLE_ENDIAN)
                ZipUtils.setZipEocdCentralDirectoryOffset(
                    this,
                    (inputZipSections.beforeSigningBlockSection.size() + outputMetadata.size).toUInt()
                )
            }


        inputZipSections.beforeSigningBlockSection.feed(outputFileChannel)
        outputFileChannel.write(ByteBuffer.wrap(outputMetadata.toByteArray()))
        inputZipSections.centralDirectorySection.feed(outputFileChannel)
        outputFileChannel.write(outputEocdRecord)
    }
}