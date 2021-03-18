package org.jetbrains.zip.signer.signer

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PasswordException
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import java.io.File
import java.io.Reader
import java.security.PrivateKey


object PrivateKeyUtils {
    /**
     * Utility function that can be used to load private key from file.
     * @param file PEM file with private key
     * @param password password required to decrypt private key
     * @return private key loaded from file
     */
    @Suppress("unused")
    @JvmStatic
    fun loadPrivateKey(file: File, password: CharArray?) = loadPrivateKey(file.readText(), password)

    /**
     * Utility function that can be used to load private key from string.
     * @param encodedPrivateKey private key in PEM format
     * @param password password required to decrypt private key
     * @return private key loaded from file
     */
    @JvmStatic
    fun loadPrivateKey(encodedPrivateKey: String, password: CharArray?): PrivateKey {
        val keyPair = loadKeyPair(encodedPrivateKey.reader(), password)
        return JcaPEMKeyConverter().getPrivateKey(keyPair.privateKeyInfo)
    }

    /**
     * @param file PEM file with private key
     * @return PEM key pair. Public key can be null if private key file contains only private key
     */
    fun loadKeyPair(file: File, password: CharArray?) = loadKeyPair(file.bufferedReader(), password)

    private fun loadKeyPair(reader: Reader, password: CharArray?): PEMKeyPair {
        val parser = PEMParser(reader)
        var pemObject = parser.readObject()
        if (pemObject is ASN1ObjectIdentifier) {
            pemObject = parser.readObject()
        }
        return extractKeyFromPemObject(pemObject, password)
    }

    private fun extractKeyFromPemObject(pemObject: Any, password: CharArray?): PEMKeyPair {
        return when (pemObject) {
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
            else -> throw IllegalArgumentException("Failed to parse private key")
        }

    }
}