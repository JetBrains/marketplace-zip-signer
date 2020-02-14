package org.jetbrains.zip.signer.keys

import org.jetbrains.zip.signer.BaseTest
import org.junit.Assert
import org.junit.Test
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey

class LoadCertificateTest : BaseTest() {
    @Test
    fun loadCertificate() {
        val privateKeyFile = getResourceFile("certificates/key.pem")
        val certificateFile = getResourceFile("certificates/certificate.pem")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromFiles(privateKeyFile, certificateFile)

        Assert.assertTrue(signerInfo.privateKey is RSAPrivateKey)
        Assert.assertTrue(signerInfo.certificates[0] is X509Certificate)
    }

    @Test
    fun loadCertificateWithPassword() {
        val privateKeyFile = getResourceFile("certificates/key_password.pem")
        val certificateFile = getResourceFile("certificates/certificate_password.pem")
        val signerInfo = SignerInfoLoader.loadSignerInfoFromFiles(
            privateKeyFile, certificateFile, "testpassword".toCharArray()
        )

        Assert.assertTrue(signerInfo.privateKey is RSAPrivateKey)
        Assert.assertTrue(signerInfo.certificates[0] is X509Certificate)
    }
}