package org.jetbrains.zip.signer.datasource

import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

interface DataSource {
    /**
     * Returns the amount of data (in bytes) contained in this data source.
     */
    fun size(): Long

    /**
     * Feeds the specified chunk from this data source into the provided channel.
     *
     * @param offset index (in bytes) at which the chunk starts inside data source
     * @param size   size (in bytes) of the chunk
     * @throws IndexOutOfBoundsException if `offset` or `size` is negative, or if
     * `offset + size` is greater than [.size].
     */
    fun feed(writableByteChannel: WritableByteChannel, offset: Long = 0, size: Long = size())

    /**
     * Returns a buffer holding the contents of the specified chunk of data from this data source.
     * Changes to the data source are not guaranteed to be reflected in the returned buffer.
     * Similarly, changes in the buffer are not guaranteed to be reflected in the data source.
     *
     *
     * The returned buffer's position is `0`, and the buffer's limit and capacity is
     * `size`.
     *
     * @param offset index (in bytes) at which the chunk starts inside data source
     * @param size   size (in bytes) of the chunk
     * @throws IndexOutOfBoundsException if `offset` or `size` is negative, or if
     * `offset + size` is greater than [.size].
     */
    fun getByteBuffer(offset: Long, size: Int): ByteBuffer

    /**
     * Copies the specified chunk from this data source into the provided destination buffer,
     * advancing the destination buffer's position by `size`.
     *
     * @param offset index (in bytes) at which the chunk starts inside data source
     * @param size   size (in bytes) of the chunk
     * @throws IndexOutOfBoundsException if `offset` or `size` is negative, or if
     * `offset + size` is greater than [.size].
     */
    fun copyTo(offset: Long, size: Int, dest: ByteBuffer)

    /**
     * Returns a data source representing the specified region of data of this data source. Changes
     * to data represented by this data source will also be visible in the returned data source.
     *
     * @param offset index (in bytes) at which the region starts inside data source
     * @param size   size (in bytes) of the region
     * @throws IndexOutOfBoundsException if `offset` or `size` is negative, or if
     * `offset + size` is greater than [.size].
     */
    fun slice(offset: Long, size: Long): DataSource
}