package org.jetbrains.zip.signer.verifier

import org.jetbrains.zip.signer.signer.CertificateUtils
import java.security.cert.X509Certificate

sealed class ZipVerificationResult

/**
 * Signature block was found in a zip archive and it's correct
 * @param certificateChains - valid certificate chains from zip metadata. Valid means that each certificate is
 * signed by the next one
 */
class SuccessfulVerificationResult(val certificateChains: List<List<X509Certificate>>) : ZipVerificationResult() {
    /**
     * Checks that zip archive was signed by the certificate chain with provided CA as root.
     * If you want to check that certificates in the chain found aren't revoked use findCertificateChain
     * @see findCertificateChain
     * @param certificateAuthority - certificate authority
     * @return true is certificate chain with provided certificate authority as root was found. False otherwise
     */
    fun isSignedBy(certificateAuthority: X509Certificate): Boolean {
        return findCertificateChain(certificateAuthority) != null
    }

    /**
     * Find the certificate chain that has provided CA as a root certificate.
     * Use this function to do further checks on found certificate chain,
     * for example, you can check that certificates in the chain aren't revoked
     * using the following utility functions
     *
     * @see CertificateUtils.getRevocationLists
     * @see CertificateUtils.findRevokedCertificate
     *
     * @param certificateAuthority - certificate authority
     * @return certificate chain with provided CA as a root certificate
     */
    fun findCertificateChain(certificateAuthority: X509Certificate): List<X509Certificate>? {
        return certificateChains.find { it.last() == certificateAuthority }
    }
}

/**
 * A signature block wasn't found in a zip archive.
 * This means that the archive wasn't signed or the signature block was corrupted
 */
object MissingSignatureResult : ZipVerificationResult()

/**
 * A signature block was found in a zip archive, but there are some problems with it.
 * Possible problems - calculated file hash digest or calculated signature of digest
 * differs from one stored in metadata.
 * This result will be returned only if the signature block was corrupted
 */
class InvalidSignatureResult(val errorMessage: String) : ZipVerificationResult()