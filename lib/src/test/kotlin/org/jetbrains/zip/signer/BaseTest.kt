package org.jetbrains.zip.signer

import java.io.File

open class BaseTest {
    fun getResourceFile(resourceFilePath: String) = File(
        javaClass.classLoader.getResource(resourceFilePath).file
    )
}