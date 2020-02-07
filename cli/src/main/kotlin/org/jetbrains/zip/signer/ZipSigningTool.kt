package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jetbrains.zip.signer.algorithm.getSuggestedSignatureAlgorithms
import org.jetbrains.zip.signer.certificates.KeystoreUtils
import org.jetbrains.zip.signer.certificates.PrivateKeyUtils
import org.jetbrains.zip.signer.certificates.X509CertificateUtils
import org.jetbrains.zip.signer.verifier.ZipVerifier
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
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

        val privateKey: PrivateKey
        val certificates: List<X509Certificate>
        if (options.keyStore != null) {
            val password =
                options.keyStorePassword ?: throw IllegalArgumentException("'ks-pass' property not specified")
            with(
                KeystoreUtils.loadPrivateKeyAndCertificateFromKeystore(
                    File(options.keyStore),
                    password,
                    options.keyStoreAlias
                )
            ) {
                privateKey = first
                certificates = second
            }
        } else {
            privateKey = PrivateKeyUtils.loadPrivateKey(File(options.privateKeyFile), options.privateKeyPassword)
            certificates = loadCertificate(options, privateKey)
        }
        val signingAlgorithms = getSuggestedSignatureAlgorithms(certificates.first().publicKey)
        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            SignerConfig(certificates, privateKey, signingAlgorithms)
        )
    }

    private fun loadCertificate(options: SigningOptions, privateKey: PrivateKey): List<X509Certificate> {
        val certificateFile = options.certificateFile
        val openSshPublicKeyFile = options.openSshPublicKeyFile
        try {
            return when {
                certificateFile != null -> X509CertificateUtils.loadCertificateFromFile(
                    File(certificateFile)
                ).toList()
                openSshPublicKeyFile != null -> listOf(
                    X509CertificateUtils.loadOpenSshKeyAsDummyCertificate(
                        File(openSshPublicKeyFile),
                        privateKey
                    )
                )
                else -> {
                    throw IllegalArgumentException(
                        "One of the following options must be specified: 'openssh-pub', 'cert'"
                    )
                }
            }
        } catch (e: IOException) {
            System.err.println("Failed to load certificate: ${e.message}")
            exitProcess(-1)
        }
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
}

class SigningOptions {
    @set:Argument("in", required = true, description = "Path to unsigned zip file")
    var inputFilePath: String = ""
    @set:Argument("out", required = true, description = "Path to signed zip file")
    var outputFilePath: String = ""
    @set:Argument("ks", required = false, description = "Keystore file")
    var keyStore: String? = null
    @set:Argument("ks-pass", required = false, description = "Keystore password")
    var keyStorePassword: String? = null
    @set:Argument("ks-key-alias", required = false, description = "Keystore key alias")
    var keyStoreAlias: String? = null
    @set:Argument("key", required = false, description = "Private key file")
    var privateKeyFile: String? = null
    @set:Argument("key-pass", required = false, description = "Private key password")
    var privateKeyPassword: String? = null
    @set:Argument("cert", required = false, description = "Certificate file")
    var certificateFile: String? = null
    @set:Argument("openssh-pub", required = false, description = "Open SSH public key file")
    var openSshPublicKeyFile: String? = null
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""
    @set:Argument("print-certs", required = false, description = "Set this option to print zip certificates")
    var printCertificates: Boolean = false
}