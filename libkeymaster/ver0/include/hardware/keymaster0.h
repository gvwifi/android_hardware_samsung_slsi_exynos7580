/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_KEYMASTER_0_H
#define ANDROID_HARDWARE_KEYMASTER_0_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <hardware/hardware.h>

__BEGIN_DECLS

/**
 * The id of this module
 */
#define KEYSTORE_HARDWARE_MODULE_ID "keystore"

#define KEYSTORE_KEYMASTER "keymaster"

/**
 * Flags for keymaster0_device::flags
 */
enum {
    KEYMASTER_SOFTWARE_ONLY = 1 << 0,
    KEYMASTER_BLOBS_ARE_STANDALONE = 1 << 1,
    KEYMASTER_SUPPORTS_DSA = 1 << 2,
    KEYMASTER_SUPPORTS_EC = 1 << 3,
};

/**
 * Asymmetric key pair types.
 */
typedef enum {
    TYPE_RSA = 1,
    TYPE_DSA = 2,
    TYPE_EC = 3,
} keymaster_keypair_t;

/**
 * Parameters needed to generate an RSA key.
 */
typedef struct {
    uint32_t modulus_size;
    uint64_t public_exponent;
} keymaster_rsa_keygen_params_t;

/**
 * Parameters needed to generate a DSA key.
 */
typedef struct {
    uint32_t key_size;
    uint32_t generator_len;
    uint32_t prime_p_len;
    uint32_t prime_q_len;
    const uint8_t* generator;
    const uint8_t* prime_p;
    const uint8_t* prime_q;
} keymaster_dsa_keygen_params_t;

/**
 * Parameters needed to generate an EC key.
 */
typedef struct {
    uint32_t field_size;
} keymaster_ec_keygen_params_t;

/**
 * Digest type.
 */
typedef enum {
    DIGEST_NONE,
} keymaster_digest_algorithm_t;

/**
 * Type of padding used for RSA operations.
 */
typedef enum {
    PADDING_NONE,
} keymaster_rsa_padding_t;

typedef struct {
    keymaster_digest_algorithm_t digest_type;
    keymaster_rsa_padding_t padding_type;
} keymaster_rsa_sign_params_t;

typedef struct {
    keymaster_digest_algorithm_t digest_type;
} keymaster_dsa_sign_params_t;

typedef struct {
    keymaster_digest_algorithm_t digest_type;
} keymaster_ec_sign_params_t;

/**
 * Keystore module for keymaster0.
 */
struct keystore_module {
    hw_module_t common;
};

/**
 * Keymaster0 device definition.
 */
struct keymaster0_device {
    struct hw_device_t common;

    uint32_t flags;

    int (*generate_keypair)(const struct keymaster0_device* dev,
            const keymaster_keypair_t key_type, const void* key_params,
            uint8_t** keyBlob, size_t* keyBlobLength);

    int (*import_keypair)(const struct keymaster0_device* dev,
            const uint8_t* key, const size_t key_length,
            uint8_t** key_blob, size_t* key_blob_length);

    int (*get_keypair_public)(const struct keymaster0_device* dev,
            const uint8_t* key_blob, const size_t key_blob_length,
            uint8_t** x509_data, size_t* x509_data_length);

    int (*delete_keypair)(const struct keymaster0_device* dev,
            const uint8_t* key_blob, const size_t key_blob_length);

    int (*delete_all)(const struct keymaster0_device* dev);

    int (*sign_data)(const struct keymaster0_device* dev,
            const void* signing_params,
            const uint8_t* key_blob, const size_t key_blob_length,
            const uint8_t* data, const size_t data_length,
            uint8_t** signed_data, size_t* signed_data_length);

    int (*verify_data)(const struct keymaster0_device* dev,
            const void* signing_params,
            const uint8_t* key_blob, const size_t key_blob_length,
            const uint8_t* signed_data, const size_t signed_data_length,
            const uint8_t* signature, const size_t signature_length);
};
typedef struct keymaster0_device keymaster0_device_t;

__END_DECLS

#endif  // ANDROID_HARDWARE_KEYMASTER_0_H
