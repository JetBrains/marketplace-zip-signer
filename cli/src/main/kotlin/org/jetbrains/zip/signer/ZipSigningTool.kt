package org.jetbrains.zip.signer

import com.sampullara.cli.Args
import com.sampullara.cli.Argument
import org.jetbrains.zip.signer.signer.SignerInfoLoader
import org.jetbrains.zip.signer.signing.ZipSigner
import org.jetbrains.zip.signer.verifier.ZipVerifier
import java.io.File
import kotlin.system.exitProcess


@ExperimentalUnsignedTypes
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

        val signerInfo = if (options.keyStore != null) {
            val password =
                options.keyStorePassword ?: throw IllegalArgumentException("'ks-pass' property not specified")
            SignerInfoLoader.loadSignerInfoFromKeystore(
                file = File(options.keyStore),
                password = password.toCharArray(),
                keystoreKeyAlias = options.keyStoreAlias,
                keystoreType = options.keyStoreType,
                keystoreProviderName = options.keyStoreProviderName
            )
        } else {
            SignerInfoLoader.loadSignerInfoFromFiles(
                File(options.privateKeyFile),
                options.certificateFile?.let { File(it) },
                options.privateKeyPassword?.toCharArray()
            )
        }

        ZipSigner.sign(
            File(options.inputFilePath),
            File(options.outputFilePath),
            signerInfo
        )
    }

    private fun verify(params: Array<String>) {
        val options = VerifyOptions()
        Args.parseOrExit(options, params)
        val signers = ZipVerifier.verify(File(options.inputFilePath))
        if (options.printCertificates) {
            signers.forEachIndexed { signerIndex, signer ->
                println("Signer #${signerIndex}")
                signer.fold(
                    { certificates ->
                        certificates.forEach { certificate ->
                            println(certificate)
                        }
                    },
                    {
                        System.err.println("Failed to verify: ${it.message}")
                    }
                )

            }
        }
    }
}

class SigningOptions {
    @set:Argument("in", required = true, description = "Path to unsigned zip file")
    var inputFilePath: String = ""
    @set:Argument("out", required = true, description = "Path to signed zip file")
    var outputFilePath: String = ""
    @set:Argument("ks", required = false, description = "KeyStore file")
    var keyStore: String? = null
    @set:Argument("ks-pass", required = false, description = "KeyStore password")
    var keyStorePassword: String? = null
    @set:Argument("ks-key-alias", required = false, description = "KeyStore key alias")
    var keyStoreAlias: String? = null
    @set:Argument("ks-type", required = false, description = "KeyStore type")
    var keyStoreType: String? = null
    @set:Argument("ks-provider-name", required = false, description = "JCA KeyStore Provider name")
    var keyStoreProviderName: String? = null
    @set:Argument("key", required = false, description = "Private key file")
    var privateKeyFile: String? = null
    @set:Argument("key-pass", required = false, description = "Private key password")
    var privateKeyPassword: String? = null
    @set:Argument("cert", required = false, description = "Certificate file")
    var certificateFile: String? = null
}

class VerifyOptions {
    @set:Argument("in", required = true, description = "Path to signed plugin zip/jar file")
    var inputFilePath: String = ""
    @set:Argument("print-certs", required = false, description = "Set this option to print zip certificates")
    var printCertificates: Boolean = false
}