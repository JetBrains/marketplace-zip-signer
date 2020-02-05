package org.jetbrains.zip.signer.signing

import org.hamcrest.CoreMatchers
import org.jetbrains.zip.signer.BaseTest
import org.jetbrains.zip.signer.utils.ZipUtils
import org.jetbrains.zip.signer.exceptions.ZipVerificationException
import org.jetbrains.zip.signer.verifier.ZipVerifier
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
            verifySigns(signs)
        }
    }

    @Test
    fun `sign than verify with other key`() {
        expectedFailure.expect(ZipVerificationException::class.java)
        expectedFailure.expectMessage(CoreMatchers.containsString("Zip archive was not signed with any of provided public keys"))

        val testFileContent = testName.methodName
        val signs = listOf(getFromKey("rsa"))
        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            verifySigns(listOf(getFromKey("dsa")))
        }
    }

    @Test
    fun `sign with cert and verify with CA`() {
        val testFileContent = testName.methodName
        val signs = listOf(getCertificate())

        createZipAndSign(testFileContent, signs).apply {
            verifyZip(testFileContent)
            ZipVerifier.verify(this, getCACertificate().certificates.first())
        }
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
            verifySigns(signs)
        }
    }

    @Test
    fun `sign and modify than verify`() {
        expectedFailure.expect(ZipVerificationException::class.java)
        expectedFailure.expectMessage(CoreMatchers.containsString("ZIP integrity check failed. CHUNKED_SHA256s digest mismatch."))

        val testFileContent = testName.methodName
        val signs = listOf(getCertificate())
        createZipAndSign(testFileContent, signs).apply {
            ZipUtils.modifyZipFile(this)
            verifyZip(testFileContent)
            verifySigns(signs)
        }
    }
}