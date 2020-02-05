/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.apk;

import com.android.apksig.util.DataSource;
import org.jetbrains.zip.signer.exceptions.SigningBlockNotFoundException;
import org.jetbrains.zip.signer.zip.ZipSections;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * APK utilities.
 */
public abstract class ApkUtils {

    private ApkUtils() {
    }

    // See https://source.android.com/security/apksigning/v2.html
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;

    /**
     * Returns the APK Signing Block of the provided APK.
     *
     * @throws IOException                   if an I/O error occurs
     * @throws SigningBlockNotFoundException if there is no APK Signing Block in the APK
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
     */
    public static ApkSigningBlock findApkSigningBlock(DataSource apk, ZipSections zipSections)
            throws IOException, SigningBlockNotFoundException {
        // FORMAT (see https://source.android.com/security/apksigning/v2.html):
        // OFFSET       DATA TYPE  DESCRIPTION
        // * @+0  bytes uint64:    size in bytes (excluding this field)
        // * @+8  bytes payload
        // * @-24 bytes uint64:    size in bytes (same as the one above)
        // * @-16 bytes uint128:   magic

        long centralDirStartOffset = zipSections.getZipCentralDirectoryOffset();
        long centralDirEndOffset =
                centralDirStartOffset + zipSections.getZipCentralDirectorySizeBytes();
        long eocdStartOffset = zipSections.getZipEndOfCentralDirectoryOffset();
        if (centralDirEndOffset != eocdStartOffset) {
            throw new SigningBlockNotFoundException(
                    "ZIP Central Directory is not immediately followed by End of Central Directory"
                            + ". CD end: " + centralDirEndOffset
                            + ", EoCD start: " + eocdStartOffset);
        }

        if (centralDirStartOffset < APK_SIG_BLOCK_MIN_SIZE) {
            throw new SigningBlockNotFoundException(
                    "APK too small for APK Signing Block. ZIP Central Directory offset: "
                            + centralDirStartOffset);
        }
        // Read the magic and offset in file from the footer section of the block:
        // * uint64:   size of block
        // * 16 bytes: magic
        ByteBuffer footer = apk.getByteBuffer(centralDirStartOffset - 24, 24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        if ((footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO)
                || (footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI)) {
            throw new SigningBlockNotFoundException(
                    "No APK Signing Block before ZIP Central Directory");
        }
        // Read and compare size fields
        long apkSigBlockSizeInFooter = footer.getLong(0);
        if ((apkSigBlockSizeInFooter < footer.capacity())
                || (apkSigBlockSizeInFooter > Integer.MAX_VALUE - 8)) {
            throw new SigningBlockNotFoundException(
                    "APK Signing Block size out of range: " + apkSigBlockSizeInFooter);
        }
        int totalSize = (int) (apkSigBlockSizeInFooter + 8);
        long apkSigBlockOffset = centralDirStartOffset - totalSize;
        if (apkSigBlockOffset < 0) {
            throw new SigningBlockNotFoundException(
                    "APK Signing Block offset out of range: " + apkSigBlockOffset);
        }
        ByteBuffer apkSigBlock = apk.getByteBuffer(apkSigBlockOffset, 8);
        apkSigBlock.order(ByteOrder.LITTLE_ENDIAN);
        long apkSigBlockSizeInHeader = apkSigBlock.getLong(0);
        if (apkSigBlockSizeInHeader != apkSigBlockSizeInFooter) {
            throw new SigningBlockNotFoundException(
                    "APK Signing Block sizes in header and footer do not match: "
                            + apkSigBlockSizeInHeader + " vs " + apkSigBlockSizeInFooter);
        }
        return new ApkSigningBlock(apkSigBlockOffset, apk.slice(apkSigBlockOffset, totalSize));
    }

    /**
     * Information about the location of the APK Signing Block inside an APK.
     */
    public static class ApkSigningBlock {
        private final long mStartOffsetInApk;
        private final DataSource mContents;

        /**
         * Constructs a new {@code ApkSigningBlock}.
         *
         * @param startOffsetInApk start offset (in bytes, relative to start of file) of the APK
         *                         Signing Block inside the APK file
         * @param contents         contents of the APK Signing Block
         */
        public ApkSigningBlock(long startOffsetInApk, DataSource contents) {
            mStartOffsetInApk = startOffsetInApk;
            mContents = contents;
        }

        /**
         * Returns the start offset (in bytes, relative to start of file) of the APK Signing Block.
         */
        public long getStartOffset() {
            return mStartOffsetInApk;
        }

        /**
         * Returns the data source which provides the full contents of the APK Signing Block,
         * including its footer.
         */
        public DataSource getContents() {
            return mContents;
        }
    }

}
