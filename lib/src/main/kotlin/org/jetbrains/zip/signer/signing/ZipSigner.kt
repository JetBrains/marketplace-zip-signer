package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.datasource.DataSource
import org.jetbrains.zip.signer.datasource.FileChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.jetbrains.zip.signer.zip.ZipSections
import org.jetbrains.zip.signer.zip.ZipUtils
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.security.cert.X509Certificate

@ExperimentalUnsignedTypes
object ZipSigner {
    @JvmStatic
    fun sign(
        inputFile: File,
        outputFile: File,
        certificates: List<X509Certificate>,
        signatureProvider: SignatureProvider
    ) {
        RandomAccessFile(inputFile, "r").use { inputRandomAccessFile ->
            RandomAccessFile(outputFile, "rw").use { outputRandomAccessFile ->
                outputRandomAccessFile.setLength(0)
                sign(
                    FileChannelDataSource(inputRandomAccessFile.channel),
                    outputRandomAccessFile.channel,
                    certificates,
                    signatureProvider
                )
            }
        }
    }

    @JvmStatic
    fun unsign(
        inputFile: File,
        outputFile: File
    ) {
        RandomAccessFile(inputFile, "r").use { inputRandomAccessFile ->
            RandomAccessFile(outputFile, "rw").use { outputRandomAccessFile ->
                outputRandomAccessFile.setLength(0)
                val inputDataSource = FileChannelDataSource(inputRandomAccessFile.channel)
                val inputZipSectionsInformation = ZipUtils.findZipSectionsInformation(inputDataSource)
                val inputSigningBlock = ZipMetadata.findInZip(inputDataSource, inputZipSectionsInformation)
                val inputZipSections =
                    ZipUtils.findZipSections(inputDataSource, inputZipSectionsInformation, inputSigningBlock)


                inputZipSections.beforeSigningBlockSection.feed(outputRandomAccessFile.channel)
                inputZipSections.centralDirectorySection.feed(outputRandomAccessFile.channel)

                val outputEocdRecord = getOutputEocdRecord(inputZipSections, 0)
                outputRandomAccessFile.channel.write(outputEocdRecord)
            }
        }
    }

    private fun sign(
        inputDataSource: DataSource,
        outputFileChannel: FileChannel,
        certificates: List<X509Certificate>,
        signatureProvider: SignatureProvider
    ) {
        if (!CertificateUtils.isValidCertificateChain(certificates)) {
            throw IllegalArgumentException("Provided certificates doesn't form a valid certificate trust chain")
        }
        val inputZipSectionsInformation = ZipUtils.findZipSectionsInformation(inputDataSource)
        val inputSigningBlock = ZipMetadata.findInZip(inputDataSource, inputZipSectionsInformation)
        val inputZipSections = ZipUtils.findZipSections(inputDataSource, inputZipSectionsInformation, inputSigningBlock)

        val outputDigests = getOutputDigests(
            inputSigningBlock, inputZipSections, signatureProvider.signatureAlgorithm.contentDigestAlgorithm
        )
        val newSignerBlock = generateSignerBlock(
            certificates = certificates,
            signatureProvider = signatureProvider,
            contentDigests = outputDigests
        )
        val outputSignerBlocks = (inputSigningBlock?.signers ?: emptyList()) + newSignerBlock
        val outputMetadata = ZipMetadata(outputDigests, outputSignerBlocks)

        generateSignedZip(inputZipSections, outputMetadata, outputFileChannel)
    }

    private fun getOutputDigests(
        inputSigningBlock: ZipMetadata?,
        inputZipSections: ZipSections,
        requiredDigest: ContentDigestAlgorithm
    ) = if (inputSigningBlock != null) {
        ZipVerifier.checkDigests(inputZipSections, inputSigningBlock)
        if (requiredDigest !in inputSigningBlock.digests.map { it.algorithm }) {
            val missingDigests = DigestUtils.computeDigest(listOf(requiredDigest), inputZipSections.toList())
            inputSigningBlock.digests + missingDigests
        } else {
            inputSigningBlock.digests
        }
    } else {
        DigestUtils.computeDigest(listOf(requiredDigest), inputZipSections.toList())
    }

    private fun generateSignedZip(
        inputZipSections: ZipSections,
        outputMetadata: ZipMetadata,
        outputFileChannel: FileChannel
    ) {
        val outputEocdRecord = getOutputEocdRecord(inputZipSections, outputMetadata.size)

        inputZipSections.beforeSigningBlockSection.feed(outputFileChannel)
        outputFileChannel.write(ByteBuffer.wrap(outputMetadata.toByteArray()))
        inputZipSections.centralDirectorySection.feed(outputFileChannel)
        outputFileChannel.write(outputEocdRecord)
    }

    private fun getOutputEocdRecord(
        inputZipSections: ZipSections,
        additionalMetadataSize: Int
    ) = inputZipSections.endOfCentralDirectorySection
        .getByteBuffer(0, inputZipSections.endOfCentralDirectorySection.size().toInt())
        .apply {
            order(ByteOrder.LITTLE_ENDIAN)
            ZipUtils.setZipEocdCentralDirectoryOffset(
                this,
                (inputZipSections.beforeSigningBlockSection.size() + additionalMetadataSize).toUInt()
            )
        }
}