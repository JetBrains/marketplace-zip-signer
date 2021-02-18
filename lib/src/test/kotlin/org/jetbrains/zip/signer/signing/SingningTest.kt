package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.BaseTest
import org.jetbrains.zip.signer.utils.ZipUtils
import org.jetbrains.zip.signer.verifier.SuccessfulVerificationResult
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.rules.TestName


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
}