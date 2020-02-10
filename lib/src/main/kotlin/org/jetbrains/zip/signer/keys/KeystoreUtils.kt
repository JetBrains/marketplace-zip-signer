package org.jetbrains.zip.signer.keys

import java.io.File

object KeystoreUtils {

    fun getKeystoreTypeFromExtension(file: File): String? {
        val fileName = file.name
        return when {
            fileName.endsWith("jks") -> "JKS"
            else -> null
        }
    }
}