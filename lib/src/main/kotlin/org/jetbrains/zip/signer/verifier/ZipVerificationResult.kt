package org.jetbrains.zip.signer.verifier

import java.security.cert.X509Certificate

sealed class ZipVerificationResult

class SuccessfulVerificationResult(val certificateChains: List<List<X509Certificate>>) : ZipVerificationResult() {
    fun isSignedBy(certificateAuthority: X509Certificate): Boolean {
        return findCertificateChain(certificateAuthority) != null
    }

    fun findCertificateChain(certificateAuthority: X509Certificate): List<X509Certificate>? {
        return certificateChains.find { it.last() == certificateAuthority }
    }
}

object MissingSignatureResult : ZipVerificationResult()

class InvalidSignatureResult(val errorMessage: String) : ZipVerificationResult()