package org.jetbrains.zip.signer.exceptions

class ZipVerificationException(override val message: String, override val cause: Throwable? = null) :
    Exception(message, cause)
