package org.jetbrains.zip.signer.keys

import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PasswordException
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import java.io.File


object PrivateKeyUtils {
    /**
     * @param file PEM file with private key
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
                else -> throw IllegalArgumentException("Failed to parse private key from $file")
            }
        }
    }
}