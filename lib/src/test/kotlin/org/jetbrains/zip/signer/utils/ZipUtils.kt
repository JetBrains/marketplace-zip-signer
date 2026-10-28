package org.jetbrains.zip.signer.utils

import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream


object ZipUtils {
    fun generateZipFile(path: Path, fileName: String, fileContent: String): File {
        Files.createDirectories(path.parent)
        val result = path.toFile()
        ZipOutputStream(FileOutputStream(result), Charsets.UTF_8).use { output ->
            with(output) {
                putNextEntry(ZipEntry(fileName))
                write(fileContent.toByteArray())
                flush()
                closeEntry()
            }
        }
        return result
    }

    fun unzipFile(zipFile: File, destDir: Path) {
        require(zipFile.isFile && zipFile.extension == "zip") { "Must be a zip archive: $zipFile" }
        Files.createDirectories(destDir)

        ZipFile(zipFile).use { zip ->
            val entries = zip.entries()

            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val path = destDir.resolve(entry.name)

                if (entry.isDirectory) {
                    Files.createDirectories(path)
                } else {
                    Files.createDirectories(path.parent)
                    BufferedInputStream(zip.getInputStream(entry)).use { input ->
                        FileOutputStream(path.toFile()).use { output ->
                            input.copyTo(output)
                        }
                    }
                }
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