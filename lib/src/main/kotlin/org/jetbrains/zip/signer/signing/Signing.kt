package org.jetbrains.zip.signer.signing

import org.jetbrains.zip.signer.metadata.Digest
import org.jetbrains.zip.signer.metadata.SignatureData
import org.jetbrains.zip.signer.metadata.SignerBlock
import org.jetbrains.zip.signer.verifier.DefaultSignatureVerifier
import org.jetbrains.zip.signer.verifier.SignatureVerifier
import java.security.SignatureException
import java.security.cert.X509Certificate

internal fun generateSignerBlock(
    certificates: List<X509Certificate>,
    signatureProvider: SignatureProvider,
    contentDigests: List<Digest>
): SignerBlock {
    if (certificates.isEmpty()) {
        throw SignatureException("No certificates configured for signer")
    }
    val encodedCertificates = certificates.map { it.encoded }
    val signatureAlgorithm = signatureProvider.signatureAlgorithm
    val digest = contentDigests.find {
        it.algorithm == signatureAlgorithm.contentDigestAlgorithm
    } ?: throw RuntimeException("${signatureAlgorithm.contentDigestAlgorithm} content digest not computed")
    val signatureVerifier = DefaultSignatureVerifier(certificates, signatureAlgorithm)
    val signature = SignatureData(
        signatureAlgorithm,
        generateSignatureOverData(digest, signatureProvider, signatureVerifier)
    )

    return SignerBlock(
        encodedCertificates,
        listOf(signature)
    )
}

private fun generateSignatureOverData(
    digest: Digest,
    signatureProvider: SignatureProvider,
    signatureVerifier: SignatureVerifier
): ByteArray {
    val signatureBytes = signatureProvider.sign(digest.digestBytes)
    signatureVerifier.verify(digest.digestBytes, signatureBytes)
    return signatureBytes
}

