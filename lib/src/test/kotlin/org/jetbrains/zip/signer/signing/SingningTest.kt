package org.jetbrains.zip.signer.signing

import junit.framework.Assert.assertTrue
import org.jetbrains.zip.signer.BaseTest
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.utils.CertificateChain
import org.jetbrains.zip.signer.utils.ZipUtils
import org.jetbrains.zip.signer.verifier.InvalidSignatureResult
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.rules.TestName
import java.io.File
import java.util.*


class SigningTest : BaseTest() {
    @get:Rule
    var testName = TestName()

    @get:Rule
    var expectedFailure = ExpectedException.none()!!

    @Test
    fun `sign than verify`() {
        val testFileContent = testName.methodName
        val signs = listOf(getCertificate())
        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            Assert.assertTrue(isSignedBy(signs))
        }
    }

    /*
     * A -> B
     *
     * Sign with chain of valid certs: B-A, but don't include the cert data; verify with A
     * */
    @Test
    fun `sign then verify but don't store the intermediate certificate`() {
        val testFileContent = testName.methodName
        val signer = getValidCertificateWithoutParents("valid")

        createZipAndSignWithChain(testFileContent, signer).apply {
            verifyZip(testFileContent)
            Assert.assertTrue(isSignedByAutoExtendCA(getRootCA()))
        }
    }

    /*
     * A -> B -> C
     *
     * Sign with chain of valid certs: C-B-A, but don't include the cert data; verify with A
     * */
    @Test
    fun `sign then verify 2 but don't pass the parent`() {
        val testFileContent = testName.methodName
        val signer = getValidCertificateWithoutParents("valid2")

        try {
            createZipAndSignWithChain(testFileContent, signer).apply {
                verifyZip(testFileContent)
                Assert.assertTrue(isSignedByAutoExtendCA(getRootCA()))
            }

            Assert.fail("Expected exception wasn't thrown")
        } catch (ze: ZipVerificationException) {
            Assert.assertEquals("Cannot build a valid certificate chain", ze.message)
        }
    }

    @Test
    fun `sign than verify ecdsa`() {
        val testFileContent = testName.methodName
        val signs = listOf(getECDSACertificate())
        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            Assert.assertTrue(isSignedBy(signs))
        }
    }

    @Test
    fun `sign than verify with other key`() {
        val testFileContent = testName.methodName
        val signs = listOf(getFromKey("rsa"))
        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            Assert.assertFalse(isSignedBy(listOf(getFromKey("dsa"))))
        }
    }

    @Test
    fun `sign with cert and verify with CA`() {
        val testFileContent = testName.methodName
        val signs = listOf(getCertificate())

        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            when (val verificationResult = ZipVerifier.verify(this)) {
                is SuccessfulVerificationResult -> Assert.assertTrue(
                    verificationResult.isSignedBy(getCACertificate().certificates.first())
                )

                else -> throw AssertionError("Invalid zip signature")
            }
        }
    }

    @Test
    fun `sign with chain and verify with CA`() {
        val testFileContent = testName.methodName
        val signs = listOf(getChain())

        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            when (val verificationResult = ZipVerifier.verify(this)) {
                is SuccessfulVerificationResult -> Assert.assertTrue(
                    verificationResult.isSignedBy(getCACertificate().certificates.first())
                )

                else -> throw AssertionError("Invalid zip signature")
            }
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `try to sign with invalid chain`() {
        val testFileContent = testName.methodName
        val signs = listOf(getInvalidChain())

        createZipAndSign(testFileContent, signs)
    }

    @Test
    fun `multiple signs different digest types`() {
        val testFileContent = testName.methodName
        val signs = listOf(
            getFromKey("rsa"),
            getFromKey("dsa"),
            getCertificate(),
            getFromKeystore(),
            getFromKeystoreWithMultipleEntries()
        )

        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            Assert.assertTrue(isSignedBy(signs))
        }
    }

    @Test
    fun `sign and modify than verify`() {
        val testFileContent = testName.methodName
        val signs = listOf(getCertificate())
        createZipAndSign(testFileContent, signs).apply {
            ZipUtils.modifyZipFile(this)
            verifyZip(testFileContent)
            Assert.assertFalse(isSignedBy(signs))
        }
    }

    @Test
    fun `unsigned file is identical to original zip`() {
        val uuid = UUID.randomUUID().toString()
        val zip = createZip(testName.methodName, uuid);
        val signedZip = sign(zip, listOf(getCertificate()))

        val unsignedFile = File(signedZip.parentFile, "$uuid-unsigned.zip")
        ZipSigner.unsign(signedZip, unsignedFile)

        zip.inputStream().use { orig ->
            unsignedFile.inputStream().use { unsigned ->
                do {
                    val origByte = orig.read()
                    Assert.assertEquals("Original and unsigned zip file differs", origByte, unsigned.read())
                } while (origByte != -1)
            }
        }
    }

    @Test
    fun `sign with sha256 and sha512 than verify`() {
        val signs = listOf(
            getSHA256Certificates(),
            getSHA512Certificates()
        )
        val testFileContent = testName.methodName
        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            Assert.assertTrue(isSignedBy(signs))
        }
    }

    @Test
    fun `handles plugins signed with an invalid certificate chain`() {
        val pluginZip = Thread.currentThread()
            .contextClassLoader
            .getResource("signed-with-invalid-chain.zip")
            ?.file
            ?.let { File(it) }
            ?: error("Missing resource file")

        val verificationResult = ZipVerifier.verify(pluginZip)

        assertTrue(verificationResult is InvalidSignatureResult)
    }

    private fun getValidCertificateWithoutParents(name: String) = CertificateChain(
        certs = listOf(
            getResourceFile("crl/validChain/$name.crt"),
        ),
        privateKeyFile = getResourceFile("crl/validChain/$name.key")
    )

    private fun getRootCA() = CertificateUtils.loadCertificatesFromFile(
        getResourceFile("crl/root/rootCA.crt"),
    ).first()
}
