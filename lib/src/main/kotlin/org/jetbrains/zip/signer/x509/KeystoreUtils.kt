package org.jetbrains.zip.signer.x509

import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object KeystoreUtils {
    fun loadPrivateKeyAndCertificateFromKeystore(
        file: File,
        password: String,
        keystoreKeyAlias: String?,
        keystoreType: String? = null
    ): Pair<PrivateKey, List<X509Certificate>> {
        val definedKeyStoreType = keystoreType
            ?: getKeystoreTypeFromExtension(file)
            ?: throw IllegalArgumentException("Can't define keystore type")
        val keyStore = KeyStore.getInstance(definedKeyStoreType)
        keyStore.load(file.inputStream().buffered(), password.toCharArray())


        var definedKeyAlias = keystoreKeyAlias
        if (definedKeyAlias == null) {
            keyStore.aliases()?.asIterator()?.forEach {
                if (keyStore.isKeyEntry(it)) {
                    if (definedKeyAlias != null) {
                        throw IllegalArgumentException(
                            "${file.absolutePath} contains multiple key entries. " +
                                    "--ks-key-alias option must be used to specify which entry to use."
                        )
                    }
                    definedKeyAlias = it
                }
            }
        }
        if (!keyStore.isKeyEntry(definedKeyAlias)) {
            throw IllegalArgumentException(
                "${file.absolutePath} entry \"$definedKeyAlias\" does not contain a key"
            )
        }
        val key = keyStore.getKey(definedKeyAlias, password.toCharArray()) as PrivateKey
        val certificateChain = keyStore.getCertificateChain(definedKeyAlias)
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw IllegalArgumentException(
                "${file.absolutePath} entry \"$definedKeyAlias\" does not contain certificates"
            )
        }
        return key to certificateChain.map { it as X509Certificate }
    }

    fun getKeystoreTypeFromExtension(file: File): String? {
        val fileName = file.name
        return when {
            fileName.endsWith("jks") -> "JKS"
            else -> null
        }
    }
}