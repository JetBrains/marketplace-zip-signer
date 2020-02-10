package org.jetbrains.zip.signer.keys

import java.io.File
import java.security.PrivateKey
import java.security.cert.X509Certificate

fun loadPrivateKeyAndCertificateFromKeystore(
    file: File,
    password: CharArray,
    keystoreKeyAlias: String?,
    keystoreType: String? = null,
    keystoreProviderName: String? = null
): Pair<PrivateKey, List<X509Certificate>> {
    val keyStore = KeystoreUtils.getKeyStore(keystoreType, keystoreProviderName)
    keyStore.load(file.inputStream().buffered(), password)
    return keyStore.getPrivateKeyAndCertificateFromKeystore(password, keystoreKeyAlias)
}

fun loadPrivateKeyAndCertificatesFromFiles(
    privateKeyFile: File,
    certificateFile: File?,
    privateKeyPassword: CharArray? = null
): Pair<PrivateKey, List<X509Certificate>> {
    val keyPair = PrivateKeyUtils.loadKeyPair(privateKeyFile, privateKeyPassword)
    val certificates = when {
        certificateFile != null -> X509CertificateUtils.loadCertificatesFromFile(certificateFile)
        else -> listOf(
            X509CertificateUtils.generateDummyCertificate(keyPair)
        )
    }
    return keyPair.private to certificates
}