package org.jetbrains.zip.signer.keys

import org.jetbrains.zip.signer.SignerInfo
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object KeystoreUtils {
    fun getKeyStore(keystoreType: String?, keystoreProviderName: String?): KeyStore {
        val definedKeyStoreType = keystoreType
            ?: KeyStore.getDefaultType()
        return if (keystoreProviderName != null) {
            KeyStore.getInstance(definedKeyStoreType, keystoreProviderName)
        } else {
            KeyStore.getInstance(definedKeyStoreType)
        }
    }
}

fun KeyStore.getSignerInfo(
    password: CharArray,
    alias: String?
): SignerInfo {
    val definedKeyAlias = alias ?: getSingleKeyEntryAlias()
    if (!isKeyEntry(definedKeyAlias)) {
        throw IllegalArgumentException(
            "Keystore entry '$definedKeyAlias' does not contain a key"
        )
    }
    val key = getKey(definedKeyAlias, password) as PrivateKey
    val certificateChain = getCertificateChain(definedKeyAlias).map { it as X509Certificate }
    if (certificateChain.isNullOrEmpty()) {
        throw IllegalArgumentException(
            "Keystore '$definedKeyAlias' does not contain certificates"
        )
    }
    return SignerInfo(certificateChain, key)
}

private fun KeyStore.getSingleKeyEntryAlias(): String? {
    var definedKeyAlias: String? = null
    aliases()
        .asSequence()
        .filter { isKeyEntry(it) }
        .forEach {
            if (definedKeyAlias != null) {
                throw IllegalArgumentException(
                    "Keystore contains multiple key entries. " +
                            "--ks-key-alias option must be used to specify which entry to use."
                )
            }
            definedKeyAlias = it
        }
    return definedKeyAlias
}