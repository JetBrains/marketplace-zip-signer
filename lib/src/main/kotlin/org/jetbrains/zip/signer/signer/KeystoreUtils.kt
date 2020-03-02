package org.jetbrains.zip.signer.signer

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object KeystoreUtils {
    @JvmOverloads
    fun getKeyStore(keystoreType: String? = null, keystoreProviderName: String? = null): KeyStore {
        val definedKeyStoreType = keystoreType ?: KeyStore.getDefaultType()
        return if (keystoreProviderName != null) {
            KeyStore.getInstance(definedKeyStoreType, keystoreProviderName)
        } else {
            KeyStore.getInstance(definedKeyStoreType)
        }
    }
}

fun KeyStore.getSignerInfo(
    keyPassword: CharArray,
    alias: String?
): SignerInfo {
    val definedKeyAlias = alias ?: getSingleKeyEntryAlias()
    if (!isKeyEntry(definedKeyAlias)) {
        throw IllegalArgumentException(
            "Keystore entry '$definedKeyAlias' does not contain a key"
        )
    }
    val key = getKey(definedKeyAlias, keyPassword) as PrivateKey
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
            requireNotNull(definedKeyAlias) {
                "Keystore contains multiple key entries. " +
                        "--ks-key-alias option must be used to specify which entry to use."
            }
            definedKeyAlias = it
        }
    return definedKeyAlias
}