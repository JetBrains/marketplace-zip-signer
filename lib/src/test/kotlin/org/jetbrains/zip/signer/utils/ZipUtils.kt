package org.jetbrains.zip.signer.utils

import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream


object ZipUtils {
    fun generateZipFile(filePath: String, fileName: String, fileContent: String): File {
        val f = File(filePath)
        f.parentFile.mkdirs()
        with(ZipOutputStream(FileOutputStream(f), Charsets.UTF_8)) {
            putNextEntry(ZipEntry(fileName))
            write(fileContent.toByteArray())
            flush()
            closeEntry()
            close()
        }
        return f
    }

    fun unzipFile(zip: File, destDir: File) {
        require(zip.isFile && zip.extension == "zip") { "Must be a zip archive: $zip" }
        destDir.mkdirs()

        val zipFile = ZipFile(zip)

        val entries = zipFile.entries()

        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()

            if (entry.isDirectory) {
                Files.createDirectories(File("$destDir/${entry.name}").toPath())
            } else {
                val file = File("$destDir/${entry.name}")
                Files.createFile(file.toPath())
                val inputStream = BufferedInputStream(zipFile.getInputStream(entry))
                val outputStream = FileOutputStream(file)
                while (inputStream.available() > 0) {
                    outputStream.write(inputStream.read())
                }
                inputStream.close()
                outputStream.close()
            }
        }
    }

    fun modifyZipFile(zip: File) {
        RandomAccessFile(zip, "rw").use {
            it.seek(100)
            it.write(1)
        }
    }
}