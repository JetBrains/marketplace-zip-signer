package org.jetbrains.zip.signer.exceptions

/**
 * Indicates that no APK Signing Block was found in an APK.
 */
class SigningBlockNotFoundException : Exception {
    constructor(message: String?) : super(message) {}
    constructor(message: String?, cause: Throwable?) : super(message, cause) {}

    companion object {
        private const val serialVersionUID = 1L
    }
}