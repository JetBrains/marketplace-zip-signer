package org.jetbrains.zip.signer.signer

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.jetbrains.zip.signer.utils.SecurityUtils
import java.io.File


object SignerInfoLoader {
    fun loadSignerInfoFromKeystore(
        file: File,
        password: CharArray,
        keyPassword: CharArray? = null,
        keystoreKeyAlias: String? = null,
        keystoreType: String? = null,
        keystoreProviderName: String? = null
    ): SignerInfo {
        val keyStore = KeystoreUtils.getKeyStore(keystoreType, keystoreProviderName)
        keyStore.load(file.inputStream().buffered(), password)
        return keyStore.getSignerInfo(keyPassword ?: password, keystoreKeyAlias)
    }

    @JvmOverloads
    fun loadSignerInfoFromFiles(
        privateKeyFile: File,
        certificateFile: File? = null,
        privateKeyPassword: CharArray? = null
    ): SignerInfo {
        SecurityUtils.addBouncyCastleProviderIfMissing()
        val keyPair = PrivateKeyUtils.loadKeyPair(privateKeyFile, privateKeyPassword)
        val certificates = when {
            certificateFile != null -> CertificateUtils.loadCertificatesFromFile(certificateFile)
            else -> listOf(
                CertificateUtils.generateDummyCertificate(keyPair)
            )
        }
        return SignerInfo(
            certificates,
            JcaPEMKeyConverter().getPrivateKey(keyPair.privateKeyInfo)
        )
    }
}