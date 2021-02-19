package org.jetbrains.zip.signer.utils

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.jetbrains.zip.signer.signer.CertificateUtils
import org.jetbrains.zip.signer.signer.PrivateKeyUtils
import java.io.File
import java.security.PrivateKey
import java.security.cert.X509Certificate

class CertificateChain(certs: List<File>, privateKeyFile: File, password: String? = null) {
  val signsChain: List<X509Certificate> = certs.map { CertificateUtils.loadCertificatesFromFile(it) }.flatten()
  val privateKey: PrivateKey = JcaPEMKeyConverter().getPrivateKey(
    PrivateKeyUtils.loadKeyPair(privateKeyFile, password?.toCharArray()).privateKeyInfo
  )

  val signCertificate: X509Certificate
    get() = signsChain.first()
}