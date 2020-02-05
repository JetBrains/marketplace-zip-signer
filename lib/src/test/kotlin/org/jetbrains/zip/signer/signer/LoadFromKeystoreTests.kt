package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.BaseTest
import org.junit.Assert
import org.junit.Test
import java.security.interfaces.RSAPrivateKey

class LoadFromKeystoreTests : BaseTest() {
    @Test
    fun `load from keystore`() {
        with(getFromKeystore()) {
            Assert.assertTrue(privateKey is RSAPrivateKey)
            Assert.assertTrue(certificates.isNotEmpty())
        }
    }

    @Test
    fun `load from keystore with multiple entries`() {
        with(getFromKeystoreWithMultipleEntries()) {
            Assert.assertTrue(privateKey is RSAPrivateKey)
            Assert.assertTrue(certificates.isNotEmpty())
        }
    }

    @Test
    fun `load from keystore with password protected key and defined provider`() {
        with(getFromKeystoreWithKeyPasswordAndProviderName()) {
            Assert.assertTrue(privateKey is RSAPrivateKey)
            Assert.assertTrue(certificates.isNotEmpty())
        }
    }
}