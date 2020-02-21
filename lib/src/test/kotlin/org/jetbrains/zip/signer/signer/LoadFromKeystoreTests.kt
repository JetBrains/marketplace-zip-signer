package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.BaseTest
import org.junit.Assert
import org.junit.Test
import java.security.interfaces.RSAPrivateKey

class LoadFromKeystoreTests : BaseTest() {
    @Test
    fun `load from keystore`() {
        val keystoreFile = getResourceFile("keystores/keystore.p12")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromKeystore(
            keystoreFile, "testpassword".toCharArray(), keystoreType = "pkcs12"
        )

        Assert.assertTrue(signerInfo.privateKey is RSAPrivateKey)
        Assert.assertTrue(signerInfo.certificates.isNotEmpty())
    }

    @Test
    fun `load from keystore with multiple entries`() {
        val keystoreFile = getResourceFile("keystores/keystore_multiple_entries.p12")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromKeystore(
            keystoreFile, "testpassword".toCharArray(), keystoreKeyAlias = "test", keystoreType = "pkcs12"
        )

        Assert.assertTrue(signerInfo.privateKey is RSAPrivateKey)
        Assert.assertTrue(signerInfo.certificates.isNotEmpty())
    }

    @Test
    fun `load from keystore with password protected key and defined provider`() {
        val keystoreFile = getResourceFile("keystores/keystore_key_password.jks")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromKeystore(
            keystoreFile,
            "testpassword".toCharArray(),
            keystoreKeyAlias = "test",
            keyPassword = "testkeypassword".toCharArray(),
            keystoreProviderName = "SUN"
        )

        Assert.assertTrue(signerInfo.privateKey is RSAPrivateKey)
        Assert.assertTrue(signerInfo.certificates.isNotEmpty())
    }
}