package org.jetbrains.zip.signer

import com.google.cloud.kms.v1.CryptoKeyVersionName
import com.google.cloud.kms.v1.Digest
import com.google.cloud.kms.v1.KeyManagementServiceClient
import com.google.protobuf.ByteString
import org.jetbrains.zip.signer.metadata.ContentDigestAlgorithm
import org.jetbrains.zip.signer.metadata.SignatureAlgorithm
import org.jetbrains.zip.signer.signing.SignatureProvider
import java.security.MessageDigest


class GoogleCloudSignatureProvider(
    private val projectId: String,
    private val locationId: String,
    private val keyRingId: String,
    private val keyId: String,
    private val keyVersion: String,
    override val signatureAlgorithm: SignatureAlgorithm
) : SignatureProvider {
    private val digester = MessageDigest.getInstance(
        signatureAlgorithm.contentDigestAlgorithm.jcaMessageDigestAlgorithm
    )

    override fun sign(dataToSign: ByteArray): ByteArray {
        KeyManagementServiceClient.create().use { client ->
            val keyName = CryptoKeyVersionName.of(projectId, locationId, keyRingId, keyId, keyVersion)
            val digestByteString = ByteString.copyFrom(digester.digest(dataToSign))
            val digest = Digest.newBuilder().apply {
                when (signatureAlgorithm.contentDigestAlgorithm) {
                    ContentDigestAlgorithm.CHUNKED_SHA256 -> this.sha256 = digestByteString
                    ContentDigestAlgorithm.CHUNKED_SHA384 -> this.sha384 = digestByteString
                    ContentDigestAlgorithm.CHUNKED_SHA512 -> this.sha512 = digestByteString
                }
            }.build()
            val response = client.asymmetricSign(keyName, digest)
            return response.signature.toByteArray()
        }
    }
}