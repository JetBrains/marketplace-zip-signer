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
package org.jetbrains.zip.signer.metadata

import org.jetbrains.zip.signer.proto.DigestProto

enum class ContentDigestAlgorithm(
    val jcaMessageDigestAlgorithm: String,
    val chunkDigestOutputSizeBytes: Int
) {
    /**
     * SHA2-256 over 1 MB chunks.
     */
    CHUNKED_SHA256("SHA-256", 256 / 8),
    /**
     * SHA2-512 over 1 MB chunks.
     */
    CHUNKED_SHA512("SHA-512", 512 / 8);

    companion object {
        fun fromProtobufEnum(protobufEnum: DigestProto.AlgorithmId) = when (protobufEnum) {
            DigestProto.AlgorithmId.SHA256 -> CHUNKED_SHA256
            DigestProto.AlgorithmId.SHA512 -> CHUNKED_SHA512
            DigestProto.AlgorithmId.UNRECOGNIZED -> throw IllegalArgumentException("Unsupported digest algorithm")
        }
    }

    fun toProtobufEnum() = when (this) {
        CHUNKED_SHA256 -> DigestProto.AlgorithmId.SHA256
        CHUNKED_SHA512 -> DigestProto.AlgorithmId.SHA512
    }
}