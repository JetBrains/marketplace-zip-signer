package org.jetbrains.zip.signer.datasource

import java.nio.channels.FileChannel

@Deprecated("Use SeekableByteChannelDataSource instead")
class FileChannelDataSource(
    private val channel: FileChannel,
    private val offset: Long = 0,
    val size: Long? = null
) : DataSource by SeekableByteChannelDataSource(channel, offset, size)