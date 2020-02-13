package org.jetbrains.zip.signer.keys

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.jetbrains.zip.signer.SignerInfo
import java.io.File

object SignerInfoLoader {
    fun loadSignerInfoFromKeystore(
        file: File,
        password: CharArray,
        keystoreKeyAlias: String?,
        keystoreType: String? = null,
        keystoreProviderName: String? = null
    ): SignerInfo {
        val keyStore = KeystoreUtils.getKeyStore(keystoreType, keystoreProviderName)
        keyStore.load(file.inputStream().buffered(), password)
        return keyStore.getSignerInfo(password, keystoreKeyAlias)
    }

    @JvmOverloads
    fun loadSignerInfoFromFiles(
        privateKeyFile: File,
        certificateFile: File? = null,
        privateKeyPassword: CharArray? = null
    ): SignerInfo {
        val keyPair = PrivateKeyUtils.loadKeyPair(privateKeyFile, privateKeyPassword)
        val certificates = when {
            certificateFile != null -> X509CertificateUtils.loadCertificatesFromFile(certificateFile)
            else -> listOf(
                X509CertificateUtils.generateDummyCertificate(keyPair)
            )
        }
        return SignerInfo(certificates, JcaPEMKeyConverter().getPrivateKey(keyPair.privateKeyInfo))
    }
}