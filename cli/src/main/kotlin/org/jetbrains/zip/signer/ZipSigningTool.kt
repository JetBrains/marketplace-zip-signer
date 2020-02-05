package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import org.jetbrains.zip.signer.algorithm.getSuggestedSignatureAlgorithms
import org.jetbrains.zip.signer.verifier.ZipVerifier
import org.jetbrains.zip.signer.x509.generateDummyCertificate
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*
import kotlin.system.exitProcess


object ZipSigningTool {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) {
            System.err.println("Command is not specified: `sign` and `verify` commands are supported.")
            exitProcess(1)
        }
        val command = args[0]
        val restParameters = args.copyOfRange(1, args.size)
        when (command) {
            "sign" -> sign(restParameters)
            "verify" -> verify(restParameters)
            else -> {
                System.err.println("Unknown command `$command`: `sign` commands are supported.")
                exitProcess(1)
            }
        }
    }

    private fun sign(params: Array<String>) {
        val options = SigningOptions()
        Args.parseOrExit(options, params)
        Security.addProvider(BouncyCastleProvider())
        val keySpec = PemReader(File(options.privateKeyFile).bufferedReader()).readPemObject()
            ?: throw IOException("Failed to read PEM object from ${options.privateKeyFile}")
        val encodedKeySpec = PKCS8EncodedKeySpec(keySpec.content)
        val privateKey =
            loadPkcs8EncodedPrivateKey(encodedKeySpec)
        val publicKey =
            loadPublicKey(File(options.publicKeyFile))
        val certificate =
            generateDummyCertificate(privateKey, publicKey)
        val signingAlgorithms =
            getSuggestedSignatureAlgorithms(publicKey)
        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            SignerConfig(certificate, privateKey, signingAlgorithms)
        )
    }

    private fun verify(params: Array<String>) {
        val options = VerifyOptions()
        Args.parseOrExit(options, params)
        val signers = ZipVerifier.verify(File(options.inputFilePath))
        if (options.printCertificates) {
            signers.forEachIndexed { signerIndex, signer ->
                signer.certs.forEach { certificate ->
                    println("Signer #${signerIndex}")
                    println(certificate)
                }
            }
        }
    }

    private fun loadPkcs8EncodedPrivateKey(spec: KeySpec): PrivateKey {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec)
        } catch (expected: InvalidKeySpecException) {
        }
        try {
            return KeyFactory.getInstance("DSA").generatePrivate(spec)
        } catch (expected: InvalidKeySpecException) {
        }
        throw InvalidKeySpecException("Not an RSA, or DSA private key")
    }

    fun loadPublicCertificate(file: File): PublicKey {
//        val pemObject = PemReader.readPemObject(file.bufferedReader())!!
        val decodedCertificateContent = CertificateFactory.getInstance("X.509")
            .generateCertificate(file.inputStream())
        val base64Encoded = file.readText().substringAfter(" ").substringBefore(" ")
        val decodedKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Encoded))
        val algorithmNameBytes = String(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val publicExponent = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val modulus = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )

        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, publicExponent))
    }

    fun loadPublicKey(file: File): PublicKey {
        val base64Encoded = file.readText().substringAfter(" ").substringBefore(" ")
        val decodedKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Encoded))
        val algorithmNameBytes = String(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val publicExponent = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )
        val modulus = BigInteger(
            readDataFromSshRsa(
                decodedKeyByteBuffer
            )
        )

        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, publicExponent))
    }

    fun readDataFromSshRsa(buffer: ByteBuffer): ByteArray {
        val dataLength = buffer.int
        val data = ByteArray(dataLength)
        buffer.get(data)
        return data
    }
}

class SigningOptions {
    @set:Argument("in", required = true, description = "Path to unsigned zip file")
    var inputFilePath: String = ""
    @set:Argument("out", required = true, description = "Path to signed zip file")
    var outputFilePath: String = ""
    @set:Argument("key", required = true, description = "Private key file")
    var privateKeyFile: String = ""
    @set:Argument("pub", required = true, description = "Public key file")
    var publicKeyFile: String = ""
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""
    @set:Argument("print-certs", required = false, description = "Set this option to print zip certificates")
    var printCertificates: Boolean = false
}