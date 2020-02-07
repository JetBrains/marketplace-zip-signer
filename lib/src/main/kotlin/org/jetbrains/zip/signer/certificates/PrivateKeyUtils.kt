package org.jetbrains.zip.signer.certificates

import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PasswordException
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import java.io.File
import java.security.PrivateKey


object PrivateKeyUtils {
    /**
     * @param file PEM file with private key
     */
    fun loadPrivateKey(file: File, password: String?): PrivateKey {
        val keyPair = PEMParser(file.bufferedReader()).readObject().let { pemObject ->
            when (pemObject) {
                is PEMEncryptedKeyPair -> {
                    if (password == null) throw PasswordException("Can't read private key. Password is missing")
                    val decryptorProvider = JcePEMDecryptorProviderBuilder().build(password.toCharArray())
                    pemObject.decryptKeyPair(decryptorProvider)
                }
                is PEMKeyPair -> pemObject
                else -> throw IllegalArgumentException("Failed to parse private key from $file")
            }
        }
        return JcaPEMKeyConverter().getPrivateKey(keyPair.privateKeyInfo)
    }
}