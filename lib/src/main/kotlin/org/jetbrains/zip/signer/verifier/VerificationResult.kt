package org.jetbrains.zip.signer.verifier

import java.security.cert.Certificate

sealed class VerificationResult
class VerificationFail(val exception: Exception) : VerificationResult()
class VerificationSuccess(certificates: List<List<Certificate>>) : VerificationResult()