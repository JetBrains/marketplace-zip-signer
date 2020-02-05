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

    private fun checkKeyLoading(
        keyName: String,
        privateKeyType: Class<out PrivateKey>,
        publicKeyType: Class<out PublicKey>,
        password: String? = null
    ) {
        val publicKey = getPublicKey(keyName)
        Assert.assertTrue(publicKeyType.isAssignableFrom(publicKey::class.java))

        with(getFromKey(keyName, password)) {
            Assert.assertTrue(privateKeyType.isAssignableFrom(privateKey::class.java))
            Assert.assertEquals(publicKey, certificates[0].publicKey)
            Assert.assertTrue(publicKeyType.isAssignableFrom(certificates[0].publicKey::class.java))
        }
    }
}