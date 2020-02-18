/*
 * Copyright (C) 2018 The Android Open Source Project
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


import kotlin.Pair;
import org.jetbrains.zip.signer.algorithm.SignatureAlgorithm;
import org.jetbrains.zip.signer.verifier.Issue;
import org.jetbrains.zip.signer.verifier.IssueWithParams;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApkSigningBlockUtils {

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    public static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;


    public static ByteBuffer findApkSignatureSchemeBlock(
            ByteBuffer apkSigningBlock,
            int blockId) throws SignatureNotFoundException {
        checkByteOrderLittleEndian(apkSigningBlock);
        // FORMAT:
        // OFFSET       DATA TYPE  DESCRIPTION
        // * @+0  bytes uint64:    size in bytes (excluding this field)
        // * @+8  bytes pairs
        // * @-24 bytes uint64:    size in bytes (same as the one above)
        // * @-16 bytes uint128:   magic
        ByteBuffer pairs = sliceFromTo(apkSigningBlock, 8, apkSigningBlock.capacity() - 24);

        int entryCount = 0;
        while (pairs.hasRemaining()) {
            entryCount++;
            if (pairs.remaining() < 8) {
                throw new SignatureNotFoundException(
                        "Insufficient data to read size of APK Signing Block entry #" + entryCount);
            }
            long lenLong = pairs.getLong();
            if ((lenLong < 4) || (lenLong > Integer.MAX_VALUE)) {
                throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount
                                + " size out of range: " + lenLong);
            }
            int len = (int) lenLong;
            int nextEntryPos = pairs.position() + len;
            if (len > pairs.remaining()) {
                throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount + " size out of range: " + len
                                + ", available: " + pairs.remaining());
            }
            int id = pairs.getInt();
            if (id == blockId) {
                return getByteBuffer(pairs, len - 4);
            }
            pairs.position(nextEntryPos);
        }

        throw new SignatureNotFoundException(
                "No APK Signature Scheme block in APK Signing Block with ID: " + blockId);
    }

    public static void checkByteOrderLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    /**
     * Returns new byte buffer whose content is a shared subsequence of this buffer's content
     * between the specified start (inclusive) and end (exclusive) positions. As opposed to
     * {@link ByteBuffer#slice()}, the returned buffer's byte order is the same as the source
     * buffer's byte order.
     */
    private static ByteBuffer sliceFromTo(ByteBuffer source, int start, int end) {
        if (start < 0) {
            throw new IllegalArgumentException("start: " + start);
        }
        if (end < start) {
            throw new IllegalArgumentException("end < start: " + end + " < " + start);
        }
        int capacity = source.capacity();
        if (end > source.capacity()) {
            throw new IllegalArgumentException("end > capacity: " + end + " > " + capacity);
        }
        int originalLimit = source.limit();
        int originalPosition = source.position();
        try {
            source.position(0);
            source.limit(end);
            source.position(start);
            ByteBuffer result = source.slice();
            result.order(source.order());
            return result;
        } finally {
            source.position(0);
            source.limit(originalLimit);
            source.position(originalPosition);
        }
    }

    /**
     * Relative <em>get</em> method for reading {@code size} number of bytes from the current
     * position of this buffer.
     *
     * <p>This method reads the next {@code size} bytes at this buffer's current position,
     * returning them as a {@code ByteBuffer} with start set to 0, limit and capacity set to
     * {@code size}, byte order set to this buffer's byte order; and then increments the position by
     * {@code size}.
     */
    private static ByteBuffer getByteBuffer(ByteBuffer source, int size) {
        if (size < 0) {
            throw new IllegalArgumentException("size: " + size);
        }
        int originalLimit = source.limit();
        int position = source.position();
        int limit = position + size;
        if ((limit < position) || (limit > originalLimit)) {
            throw new BufferUnderflowException();
        }
        source.limit(limit);
        try {
            ByteBuffer result = source.slice();
            result.order(source.order());
            source.position(limit);
            return result;
        } finally {
            source.limit(originalLimit);
        }
    }

    public static String toHex(byte[] value) {
        StringBuilder sb = new StringBuilder(value.length * 2);
        int len = value.length;
        for (int i = 0; i < len; i++) {
            int hi = (value[i] & 0xff) >>> 4;
            int lo = value[i] & 0x0f;
            sb.append(HEX_DIGITS[hi]).append(HEX_DIGITS[lo]);
        }
        return sb.toString();
    }

    public static class SignatureNotFoundException extends Exception {
        private static final long serialVersionUID = 1L;

        public SignatureNotFoundException(String message) {
            super(message);
        }

        public SignatureNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * uses the SignatureAlgorithms in the provided signerConfig to sign the provided data
     *
     * @return list of signature algorithm IDs and their corresponding signatures over the data.
     */
    public static List<Pair<Integer, byte[]>> generateSignaturesOverData(
            SignerConfig signerConfig, byte[] data)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        List<Pair<Integer, byte[]>> signatures =
                new ArrayList<>(signerConfig.signatureAlgorithms.size());
        PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.signatureAlgorithms) {
            Pair<String, ? extends AlgorithmParameterSpec> sigAlgAndParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams();
            String jcaSignatureAlgorithm = sigAlgAndParams.getFirst();
            AlgorithmParameterSpec jcaSignatureAlgorithmParams = sigAlgAndParams.getSecond();
            byte[] signatureBytes;
            try {
                Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                signature.initSign(signerConfig.privateKey);
                if (jcaSignatureAlgorithmParams != null) {
                    signature.setParameter(jcaSignatureAlgorithmParams);
                }
                signature.update(data);
                signatureBytes = signature.sign();
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e);
            } catch (InvalidAlgorithmParameterException | SignatureException e) {
                throw new SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e);
            }

            try {
                Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                signature.initVerify(publicKey);
                if (jcaSignatureAlgorithmParams != null) {
                    signature.setParameter(jcaSignatureAlgorithmParams);
                }
                signature.update(data);
                if (!signature.verify(signatureBytes)) {
                    throw new SignatureException("Failed to verify generated "
                            + jcaSignatureAlgorithm
                            + " signature using public key from certificate");
                }
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException(
                        "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                                + " public key from certificate", e);
            } catch (InvalidAlgorithmParameterException | SignatureException e) {
                throw new SignatureException(
                        "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                                + " public key from certificate", e);
            }

            signatures.add(new Pair(signatureAlgorithm.getId(), signatureBytes));
        }
        return signatures;
    }

    /**
     * Signer configuration.
     */
    public static class SignerConfig {
        /**
         * Private key.
         */
        public PrivateKey privateKey;

        /**
         * Certificates, with the first certificate containing the public key corresponding to
         * {@link #privateKey}.
         */
        public List<X509Certificate> certificates;

        /**
         * List of signature algorithms with which to sign.
         */
        public List<SignatureAlgorithm> signatureAlgorithms;
    }


    public static class SupportedSignature {
        public final SignatureAlgorithm algorithm;
        public final byte[] signature;

        public SupportedSignature(SignatureAlgorithm algorithm, byte[] signature) {
            this.algorithm = algorithm;
            this.signature = signature;
        }
    }

    public static class Result {
        public final int signatureSchemeVersion;

        /**
         * Whether the APK's APK Signature Scheme signature verifies.
         */
        public boolean verified;

        public final List<SignerInfo> signers = new ArrayList<>();
        private final List<IssueWithParams> mWarnings = new ArrayList<>();
        private final List<IssueWithParams> mErrors = new ArrayList<>();

        public Result(int signatureSchemeVersion) {
            this.signatureSchemeVersion = signatureSchemeVersion;
        }

        public boolean containsErrors() {
            if (!mErrors.isEmpty()) {
                return true;
            }
            if (!signers.isEmpty()) {
                for (SignerInfo signer : signers) {
                    if (signer.containsErrors()) {
                        return true;
                    }
                }
            }
            return false;
        }

        public void addError(Issue msg, Object... parameters) {
            mErrors.add(new IssueWithParams(msg, parameters));
        }

        public void addWarning(Issue msg, Object... parameters) {
            mWarnings.add(new IssueWithParams(msg, parameters));
        }

        public List<IssueWithParams> getErrors() {
            return mErrors;
        }

        public List<IssueWithParams> getWarnings() {
            return mWarnings;
        }

        public static class SignerInfo {
            public int index;
            public List<X509Certificate> certs = new ArrayList<>();
            public List<ContentDigest> contentDigests = new ArrayList<>();
            public Map<ContentDigestAlgorithm, byte[]> verifiedContentDigests = new HashMap<>();
            public List<Signature> signatures = new ArrayList<>();
            public Map<SignatureAlgorithm, byte[]> verifiedSignatures = new HashMap<>();
            public byte[] signedData;

            private final List<IssueWithParams> mWarnings = new ArrayList<>();
            private final List<IssueWithParams> mErrors = new ArrayList<>();

            public void addError(Issue msg, Object... parameters) {
                mErrors.add(new IssueWithParams(msg, parameters));
            }

            public void addWarning(Issue msg, Object... parameters) {
                mWarnings.add(new IssueWithParams(msg, parameters));
            }

            public boolean containsErrors() {
                return !mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return mWarnings;
            }

            public static class ContentDigest {
                private final int mSignatureAlgorithmId;
                private final byte[] mValue;

                public ContentDigest(int signatureAlgorithmId, byte[] value) {
                    mSignatureAlgorithmId = signatureAlgorithmId;
                    mValue = value;
                }

                public int getSignatureAlgorithmId() {
                    return mSignatureAlgorithmId;
                }

                public byte[] getValue() {
                    return mValue;
                }
            }

            public static class Signature {
                private final int mAlgorithmId;
                private final byte[] mValue;

                public Signature(int algorithmId, byte[] value) {
                    mAlgorithmId = algorithmId;
                    mValue = value;
                }

                public int getAlgorithmId() {
                    return mAlgorithmId;
                }

                public byte[] getValue() {
                    return mValue;
                }
            }

            public static class AdditionalAttribute {
                private final int mId;
                private final byte[] mValue;

                public AdditionalAttribute(int id, byte[] value) {
                    mId = id;
                    mValue = value.clone();
                }

                public int getId() {
                    return mId;
                }

                public byte[] getValue() {
                    return mValue.clone();
                }
            }
        }
    }
}
