package org.jetbrains.zip.signer.exceptions

class PluginFormatException : Exception {
    constructor(message: String) : super(message)
    constructor(message: String, cause: Throwable) : super(message, cause)
}