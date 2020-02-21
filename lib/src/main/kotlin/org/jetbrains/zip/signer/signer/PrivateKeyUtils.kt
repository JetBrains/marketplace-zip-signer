package org.jetbrains.zip.signer.signer

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PasswordException
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import java.io.File


object PrivateKeyUtils {
    /**
     * @param file PEM file with private key
     * @return PEM key pair. Public key can be null if private key file contains only private key
     */
    fun loadKeyPair(file: File, password: CharArray?): PEMKeyPair {
        return PEMParser(file.bufferedReader()).readObject().let { pemObject ->
            when (pemObject) {
                is PEMEncryptedKeyPair -> {
                    if (password == null) throw PasswordException("Can't read private key. Password is missing")
                    val decryptorProvider = JcePEMDecryptorProviderBuilder().build(password)
                    pemObject.decryptKeyPair(decryptorProvider)
                }
                is PEMKeyPair -> pemObject
                is PKCS8EncryptedPrivateKeyInfo -> {
                    if (password == null) throw PasswordException("Can't read private key. Password is missing")
                    val decryptorProvider = JceOpenSSLPKCS8DecryptorProviderBuilder().build(password)
                    val privateKey = pemObject.decryptPrivateKeyInfo(decryptorProvider)
                    PEMKeyPair(null, privateKey)
                }
                is PrivateKeyInfo -> PEMKeyPair(null, pemObject)
                else -> throw IllegalArgumentException("Failed to parse private key from $file")
            }
        }
    }
}