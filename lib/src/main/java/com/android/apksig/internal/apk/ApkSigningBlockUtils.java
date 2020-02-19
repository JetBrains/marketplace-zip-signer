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


import org.jetbrains.zip.signer.algorithm.SignatureAlgorithm;
import org.jetbrains.zip.signer.verifier.Issue;
import org.jetbrains.zip.signer.verifier.IssueWithParams;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApkSigningBlockUtils {

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    public static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;


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
