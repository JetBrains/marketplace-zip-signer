package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.BaseTest
import org.junit.Assert
import org.junit.Test
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey


class LoadKeysTests : BaseTest() {
    @Test
    fun testLoadRsaKeyPair() = checkKeyLoading(
        "rsa", RSAPrivateKey::class.java, RSAPublicKey::class.java
    )

    @Test
    fun testLoadPasswordProtectedRsaKeyPair() = checkKeyLoading(
        "rsa_password", RSAPrivateKey::class.java, RSAPublicKey::class.java, "testpassword"
    )

    @Test
    fun testLoadDsaKeyPair() = checkKeyLoading(
        "dsa", DSAPrivateKey::class.java, DSAPublicKey::class.java
    )

    @Test
    fun testLoadPasswordProtectedDsaKeyPair() = checkKeyLoading(
        "dsa_password", DSAPrivateKey::class.java, DSAPublicKey::class.java, "testpassword"
    )

    fun checkKeyLoading(
        keyName: String,
        privateKeyType: Class<out PrivateKey>,
        publicKeyType: Class<out PublicKey>,
        password: String? = null
    ) {
        val privateKeyFile = getResourceFile("keypairs/$keyName")
        val publicKeyFile = getResourceFile("keypairs/$keyName.pub")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromFiles(
            privateKeyFile, privateKeyPassword = password?.toCharArray()
        )
        val publicKey = PublicKeyUtils.loadOpenSshKey(publicKeyFile)

        Assert.assertTrue(privateKeyType.isAssignableFrom(signerInfo.privateKey::class.java))
        Assert.assertTrue(publicKeyType.isAssignableFrom(publicKey::class.java))
        Assert.assertEquals(publicKey, signerInfo.certificates[0].publicKey)
    }
}