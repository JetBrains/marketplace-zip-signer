package org.jetbrains.zip.signer.signer

import org.jetbrains.zip.signer.BaseTest
import org.junit.Assert
import org.junit.Test
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey

class LoadCertificateTest : BaseTest() {
    @Test
    fun loadCertificate() {
        with(getCertificate()) {
            Assert.assertTrue(privateKey is RSAPrivateKey)
            Assert.assertTrue(certificates[0] is X509Certificate)
        }
    }

    @Test
    fun loadCertificateWithPassword() {
        with(getCertificateWithPassword()) {
            Assert.assertTrue(privateKey is RSAPrivateKey)
            Assert.assertTrue(certificates[0] is X509Certificate)
        }
    }
}