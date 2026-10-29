package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.BaseTest
import org.jetbrains.zip.signer.datasource.SeekableByteChannelDataSource
import org.jetbrains.zip.signer.digest.DigestUtils
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.metadata.ZipMetadata
import org.jetbrains.zip.signer.signer.PublicKeyUtils
import org.jetbrains.zip.signer.signer.SignerInfo
import org.jetbrains.zip.signer.verifier.InvalidSignatureResult
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.jetbrains.zip.signer.zip.ZipSections
import org.jetbrains.zip.signer.zip.ZipUtils
import org.jetbrains.zip.signer.zip.ZipUtils.getModifiedEocdRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.util.UUID

@OptIn(ExperimentalUnsignedTypes::class)
class DigestTest : BaseTest() {
    @Test
    fun `multiple digest accepted`() {
        val signerInfo = getCertificate()

        val original = createZipAndSign("original", listOf(signerInfo))
        val allDigests = ContentDigestAlgorithm.entries.map {
            digest(original, it)
        }

        val replaced = substituteDigestAndContent(original, original, allDigests)
        val verificationResult = ZipVerifier.verify(replaced)
        assertTrue(verificationResult is SuccessfulVerificationResult)
    }

    @Test
    fun `duplicate digest accepted`() {
        val signerInfo = getCertificate()
        val algorithm = signerInfo.suggestedSignatureAlgorithm()

        val original = createZipAndSign("original", listOf(signerInfo))
        val digest = digest(original, algorithm.contentDigestAlgorithm)

        val replaced = substituteDigestAndContent(original, original, listOf(digest, digest))
        val verificationResult = ZipVerifier.verify(replaced)
        assertTrue(verificationResult is SuccessfulVerificationResult)
    }

    @Test
    fun `missing digest is rejected`() {
        val signerInfo = getCertificate()
        val original = createZipAndSign("original", listOf(signerInfo))

        val replaced = substituteDigestAndContent(original, original, emptyList())
        val verificationResult = ZipVerifier.verify(replaced)
        require(verificationResult is InvalidSignatureResult) {
            "Zip archive with missing digest was accepted"
        }
        assertEquals("No content digests in ZIP metadata", verificationResult.errorMessage)
    }

    @Test
    fun `wrong digest type is rejected`() {
        val signerInfo = getCertificate()
        val algorithm = signerInfo.suggestedSignatureAlgorithm()
        val wrongAlgorithm = ContentDigestAlgorithm.entries.first { it != algorithm.contentDigestAlgorithm }

        val original = createZipAndSign("original", listOf(signerInfo))
        val wrongDigestType = digest(original, wrongAlgorithm)

        val replaced = substituteDigestAndContent(original, original, listOf(wrongDigestType))
        val verificationResult = ZipVerifier.verify(replaced)
        require(verificationResult is InvalidSignatureResult) {
            "Zip archive with wrong digest was accepted"
        }
        assertEquals("Missing digest ${algorithm.contentDigestAlgorithm}", verificationResult.errorMessage)
    }

    @Test
    fun `conflicting digest records are rejected in either order`() {
        val signerInfo = getCertificate()
        val algorithm = signerInfo.suggestedSignatureAlgorithm()

        val original = createZipAndSign("original", listOf(signerInfo))
        val originalDigest = digest(original, algorithm.contentDigestAlgorithm)

        val modified = createZip("modified", UUID.randomUUID().toString())
        val modifiedDigest = digest(modified, algorithm.contentDigestAlgorithm)

        listOf(
            originalDigest to modifiedDigest,
            modifiedDigest to originalDigest
        ).forEach { (digest1, digest2) ->
            val replaced = substituteDigestAndContent(original, modified, listOf(digest1, digest2))
            val verificationResult = ZipVerifier.verify(replaced)
            require(verificationResult is InvalidSignatureResult) {
                "Zip archive with modified body and conflicting digest was accepted"
            }
            assertEquals(
                "ZIP integrity check failed. ${algorithm.contentDigestAlgorithm} digest mismatch.",
                verificationResult.errorMessage
            )
        }
    }


    @OptIn(ExperimentalUnsignedTypes::class)
    private fun digest(
        zip: File,
        algorithm: ContentDigestAlgorithm
    ): Digest = FileChannel.open(zip.toPath(), READ).use { channel ->
        val source = SeekableByteChannelDataSource(channel)
        val info = ZipUtils.findZipSectionsInformation(source)
        val zipMetadata = ZipMetadata.findInZip(source, info)
        val zipSections = ZipUtils.findZipSections(source, info, zipMetadata)

         DigestUtils.computeDigest(
            listOf(algorithm),
            zipSections
        ).single()
    }

    private fun substituteDigestAndContent(
        signedZip: File,
        contentZip: File,
        digests: List<Digest>
    ): Path {
        val outputZip = createTempZip("output")

        val newMetadata = withZipData(signedZip) { _, metadataWithSignature ->
            ZipMetadata(digests, requireNotNull(metadataWithSignature).signers)
        }

        withZipData(contentZip) { content, _ ->
            FileChannel.open(outputZip, CREATE, TRUNCATE_EXISTING, WRITE).use { output ->
                output.writeSignedZip(content, newMetadata)
            }
        }

        return outputZip
    }


    private fun <T> withZipData(
        input: File,
        callable: (ZipSections, ZipMetadata?) -> T
    ): T {
        return FileChannel.open(input.toPath(), READ).use { channel ->
            val source = SeekableByteChannelDataSource(channel)
            val info = ZipUtils.findZipSectionsInformation(source)
            val metadata = ZipMetadata.findInZip(source, info)
            val sections = ZipUtils.findZipSections(source, info, metadata)

            callable(sections, metadata)
        }
    }

    private fun FileChannel.writeSignedZip(
        inputZipSections: ZipSections,
        outputMetadata: ZipMetadata,
    ) {
        val outputEocdRecord = getModifiedEocdRecord(inputZipSections, outputMetadata.size)

        inputZipSections.beforeSigningBlockSection.feed(this)
        write(ByteBuffer.wrap(outputMetadata.toByteArray()))
        inputZipSections.centralDirectorySection.feed(this)
        write(outputEocdRecord)
    }

    private fun SignerInfo.suggestedSignatureAlgorithm() =
        PublicKeyUtils.getSuggestedSignatureAlgorithm(certificates[0].publicKey)
}
