/* rust-spdm-minimal FFI header */

#ifndef RUST_SPDM_MINIMAL_H
#define RUST_SPDM_MINIMAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_SESSIONS 4

#define MAX_HASH_SIZE 64

#define MAX_SPDM_MSG_SIZE 4096

#define TRANSCRIPT_A_SIZE 2048

#define SCRATCH_BUFFER_SIZE 4096

/**
 * Requester Capability Flags
 */
#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP 2

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP 4

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP 8

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP 64

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP 256

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP 512

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP 4096

#define SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP 8192

/**
 * Responder Capability Flags
 */
#define SPDM_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP 2

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP 4

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP 24

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG 8

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG 16

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP 64

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP 128

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP 256

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP 512

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_SESSION_CAP 1024

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP 2048

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP 16384

#define SPDM_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP 65536

/**
 * Base Hash Algorithm Flags
 */
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 2

#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 4

#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 8

/**
 * Base Asymmetric Algorithm Flags
 */
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 16

#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 32

#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 64

#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 128

#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 256

/**
 * DHE Group Flags
 */
#define SPDM_ALGORITHMS_DHE_ALGO_FFDHE_2048 1

#define SPDM_ALGORITHMS_DHE_ALGO_FFDHE_3072 2

#define SPDM_ALGORITHMS_DHE_ALGO_FFDHE_4096 4

#define SPDM_ALGORITHMS_DHE_ALGO_SECP256R1 8

#define SPDM_ALGORITHMS_DHE_ALGO_SECP384R1 16

/**
 * AEAD Cipher Suite Flags
 */
#define SPDM_ALGORITHMS_AEAD_ALGO_AES_128_GCM 1

#define SPDM_ALGORITHMS_AEAD_ALGO_AES_256_GCM 2

#define SPDM_ALGORITHMS_AEAD_ALGO_CHACHA20_POLY1305 4

/**
 * Measurement Specification Flags
 */
#define SPDM_MEASUREMENT_SPEC_DMTF 1

/**
 * Measurement Hash Algorithm Flags
 */
#define SPDM_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM 1

#define SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 2

#define SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 4

#define KEY_EXCHANGE_REQUEST_MIN_SIZE (SpdmMessageHeader_SIZE + 8)

#define KEY_EXCHANGE_RESPONSE_MIN_SIZE (SpdmMessageHeader_SIZE + 10)

#define END_SESSION_REQUEST_SIZE (SpdmMessageHeader_SIZE + 2)

#define END_SESSION_RESPONSE_SIZE (SpdmMessageHeader_SIZE + 2)

#define SHA256_SIZE 32

#define SHA384_SIZE 48

#define AES128_KEY_SIZE 16

#define AES256_KEY_SIZE 32

#define GCM_IV_SIZE 12

#define GCM_TAG_SIZE 16

#define P256_PUBLIC_KEY_SIZE 65

#define P256_PRIVATE_KEY_SIZE 32

#define P256_SHARED_SECRET_SIZE 32

#define P384_PUBLIC_KEY_SIZE 97

#define P384_PRIVATE_KEY_SIZE 48

#define P384_SHARED_SECRET_SIZE 48

#define ECDSA_P256_SIGNATURE_SIZE 64

#define ECDSA_P384_SIGNATURE_SIZE 96

#define HKDF_SHA256_HASH_SIZE 32

#define HKDF_SHA384_HASH_SIZE 48

#define MAX_SESSION_COUNT 8

#define MAX_KEY_SIZE SHA384_SIZE

#define AEAD_TAG_SIZE 16

#define AEAD_IV_SIZE 12

#define SECURED_MESSAGE_HEADER_SIZE 6

#define LIBSPDM_STATUS_SUCCESS 0

#define LIBSPDM_STATUS_ERROR 1

#define LIBSPDM_STATUS_BUSY 2

#define LIBSPDM_STATUS_RESYNC 3

#define LIBSPDM_STATUS_BUFFER_FULL 4

#define LIBSPDM_STATUS_BUFFER_TOO_SMALL 5

typedef uint32_t libspdm_return_t;

typedef void *libspdm_context_t;

typedef uint32_t libspdm_session_id_t;

typedef struct libspdm_data_parameter_t {
  uint8_t location;
  uint8_t additional_data[4];
} libspdm_data_parameter_t;

typedef void *pci_ide_km_context_t;

typedef struct pci_ide_km_key_set_t {
  uint8_t key_id;
  uint8_t key_select;
  uint8_t key[32];
} pci_ide_km_key_set_t;

libspdm_return_t libspdm_init_context(libspdm_context_t context);

libspdm_return_t libspdm_get_version(libspdm_context_t context,
                                     uint8_t *version_count,
                                     uint32_t *version_number_entry);

libspdm_return_t libspdm_get_capabilities(libspdm_context_t context);

libspdm_return_t libspdm_negotiate_algorithms(libspdm_context_t context);

libspdm_return_t libspdm_get_digests(libspdm_context_t context,
                                     uint8_t *slot_mask,
                                     uint8_t *total_digest_buffer);

libspdm_return_t libspdm_get_certificate(libspdm_context_t context,
                                         uint8_t slot_id,
                                         uintptr_t *cert_chain_size,
                                         uint8_t *cert_chain);

libspdm_return_t libspdm_key_exchange(libspdm_context_t context,
                                      uint8_t measurement_hash_type,
                                      uint8_t slot_id,
                                      libspdm_session_id_t *session_id,
                                      uint8_t *heartbeat_period,
                                      uint8_t *measurement_summary_hash);

libspdm_return_t libspdm_finish(libspdm_context_t context,
                                libspdm_session_id_t session_id,
                                uint8_t slot_id,
                                uint8_t request_attribute);

libspdm_return_t libspdm_end_session(libspdm_context_t context,
                                     libspdm_session_id_t session_id,
                                     uint8_t end_session_attributes);

libspdm_return_t libspdm_start_session(libspdm_context_t context, libspdm_session_id_t session_id);

libspdm_return_t libspdm_stop_session(libspdm_context_t context, libspdm_session_id_t session_id);

libspdm_return_t libspdm_send_receive_data(libspdm_context_t context,
                                           libspdm_session_id_t session_id,
                                           const uint8_t *request,
                                           uintptr_t request_size,
                                           uint8_t *response,
                                           uintptr_t *response_size);

libspdm_return_t libspdm_get_data(libspdm_context_t context,
                                  uint32_t data_type,
                                  const struct libspdm_data_parameter_t *parameter,
                                  void *data,
                                  uintptr_t *data_size);

libspdm_return_t libspdm_set_data(libspdm_context_t context,
                                  uint32_t data_type,
                                  const struct libspdm_data_parameter_t *parameter,
                                  const void *data,
                                  uintptr_t data_size);

libspdm_return_t libspdm_process_message(libspdm_context_t context,
                                         libspdm_session_id_t session_id,
                                         const uint8_t *message,
                                         uintptr_t message_size);

libspdm_return_t libspdm_register_get_response_func(libspdm_context_t context,
                                                    void *get_response_func);

bool libspdm_is_session_established(libspdm_context_t context, libspdm_session_id_t session_id);

void *libspdm_get_session_info(libspdm_context_t context, libspdm_session_id_t session_id);

libspdm_return_t libspdm_secured_message_send_receive(libspdm_context_t context,
                                                      libspdm_session_id_t session_id,
                                                      const uint8_t *request,
                                                      uintptr_t request_size,
                                                      uint8_t *response,
                                                      uintptr_t *response_size);

libspdm_return_t libspdm_generate_nonce(libspdm_context_t context,
                                        uint8_t *nonce,
                                        uintptr_t nonce_size);

void libspdm_free_context(libspdm_context_t context);

libspdm_return_t libspdm_reset_context(libspdm_context_t context);

libspdm_return_t pci_ide_km_query(pci_ide_km_context_t context,
                                  uint32_t session_id,
                                  uint8_t port_index,
                                  uint8_t *query_result);

libspdm_return_t pci_ide_km_set_key(pci_ide_km_context_t context,
                                    uint32_t session_id,
                                    uint8_t port_index,
                                    const struct pci_ide_km_key_set_t *key_set);

libspdm_return_t pci_ide_km_get_key(pci_ide_km_context_t context,
                                    uint32_t session_id,
                                    uint8_t port_index,
                                    uint8_t key_id,
                                    struct pci_ide_km_key_set_t *key_set);

libspdm_return_t pci_ide_km_key_prog(pci_ide_km_context_t context,
                                     uint32_t session_id,
                                     uint8_t port_index,
                                     const struct pci_ide_km_key_set_t *key_set);

#endif /* RUST_SPDM_MINIMAL_H */
