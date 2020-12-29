package org.jetbrains.zip.signer.verifier

import org.jetbrains.zip.signer.signer.CertificateUtils
import java.security.cert.Certificate

sealed class ZipVerificationResult

class SuccessfulVerificationResult(val certificateChains: List<List<Certificate>>) : ZipVerificationResult() {
    fun isSignedBy(certificateAuthority: Certificate): Boolean {
        return certificateChains.any { CertificateUtils.isCertificateChainTrusted(it, certificateAuthority) }
    }
}

class MissingSignatureResult : ZipVerificationResult()

class InvalidSignatureResult(val errorMessage: String) : ZipVerificationResult()