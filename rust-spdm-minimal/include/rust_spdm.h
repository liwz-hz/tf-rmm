/* rust-spdm-minimal FFI header */

#ifndef RUST_SPDM_MINIMAL_H
#define RUST_SPDM_MINIMAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_SESSIONS 4

#define MAX_HASH_SIZE_CTX 64

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

#define MAX_HASH_SIZE SHA384_SIZE

#define AES128_KEY_SIZE 16

#define AES256_KEY_SIZE 32

#define GCM_IV_SIZE 12

#define GCM_TAG_SIZE 16

#define P256_PUBLIC_KEY_SIZE 65

#define P256_PRIVATE_KEY_SIZE 32

#define P256_SHARED_SECRET_SIZE 32

#define P384_PUBLIC_KEY_SIZE 97

#define P384_PUBLIC_KEY_RAW_SIZE 96

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

#define LIBSPDM_STATUS_BUFFER_TOO_SMALL 2147483655

#define LIBSPDM_STATUS_CRYPTO_ERROR 2147483651

#define LIBSPDM_STATUS_INVALID_MSG_FIELD 2147483652

#define LIBSPDM_STATUS_INVALID_MSG_SIZE 2147483653

#define LIBSPDM_STATUS_UNSUPPORTED_CAP 2147483650

#define LIBSPDM_STATUS_RECEIVE_FAIL 2147745793

#define LIBSPDM_SESSION_STATE_NOT_STARTED 0

#define LIBSPDM_SESSION_STATE_HANDSHAKING 1

#define LIBSPDM_SESSION_STATE_ESTABLISHED 2

#define SPDM_KEY_EXCHANGE 228

#define SPDM_KEY_EXCHANGE_RSP 100

#define SPDM_FINISH 229

#define SPDM_FINISH_RSP 101

#define LIBSPDM_DATA_SPDM_VERSION 0

#define LIBSPDM_DATA_SECURED_MESSAGE_VERSION 1

#define LIBSPDM_DATA_CAPABILITY_FLAGS 2

#define LIBSPDM_DATA_CAPABILITY_CT_EXPONENT 3

#define LIBSPDM_DATA_CAPABILITY_RTT_US 4

#define LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE 5

#define LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE 6

#define LIBSPDM_DATA_MEASUREMENT_SPEC 8

#define LIBSPDM_DATA_BASE_ASYM_ALGO 10

#define LIBSPDM_DATA_BASE_HASH_ALGO 11

#define LIBSPDM_DATA_DHE_NAME_GROUP 12

#define LIBSPDM_DATA_AEAD_CIPHER_SUITE 13

#define LIBSPDM_DATA_REQ_BASE_ASYM_ALG 14

#define LIBSPDM_DATA_KEY_SCHEDULE 15

#define LIBSPDM_DATA_OTHER_PARAMS_SUPPORT 16

#define LIBSPDM_DATA_CONNECTION_STATE 18

#define LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER 31

#define LIBSPDM_DATA_PEER_USED_CERT_CHAIN_HASH 60

#define LIBSPDM_CONNECTION_STATE_NOT_STARTED 0

#define LIBSPDM_CONNECTION_STATE_AFTER_VERSION 1

#define LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES 2

#define LIBSPDM_CONNECTION_STATE_NEGOTIATED 3

#define LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS 4

#define LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE 5

#define LIBSPDM_CONNECTION_STATE_AUTHENTICATED 6

#define SPDM_CHALLENGE 131

#define SPDM_CHALLENGE_AUTH 3

#define PCI_PROTOCOL_ID_TDISP 1

#define PCI_TDISP_MESSAGE_VERSION_10 16

#define PCI_TDISP_GET_VERSION 129

#define PCI_TDISP_GET_CAPABILITIES 130

#define PCI_TDISP_LOCK_INTERFACE_REQ 131

#define PCI_TDISP_GET_DEVICE_INTERFACE_REPORT 132

#define PCI_TDISP_GET_DEVICE_INTERFACE_STATE 133

#define PCI_TDISP_START_INTERFACE_REQ 134

#define PCI_TDISP_STOP_INTERFACE_REQ 135

#define PCI_TDISP_VERSION 1

#define PCI_TDISP_CAPABILITIES 2

#define PCI_TDISP_LOCK_INTERFACE_RSP 3

#define PCI_TDISP_DEVICE_INTERFACE_REPORT 4

#define PCI_TDISP_DEVICE_INTERFACE_STATE 5

#define PCI_TDISP_START_INTERFACE_RSP 6

#define PCI_TDISP_STOP_INTERFACE_RSP 7

#define PCI_TDISP_ERROR 127

#define PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED 0

#define PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED 1

#define PCI_TDISP_INTERFACE_STATE_RUN 2

#define PCI_TDISP_INTERFACE_STATE_ERROR 3

#define SPDM_VENDOR_DEFINED_REQUEST 254

#define SPDM_VENDOR_DEFINED_RESPONSE 126

#define SPDM_STANDARD_ID_PCISIG 3

#define SPDM_VENDOR_ID_PCISIG 1

#define PCI_TDISP_START_INTERFACE_NONCE_SIZE 32

typedef uint32_t libspdm_return_t;

typedef void *libspdm_context_t;

typedef struct libspdm_data_parameter_t {
  uint8_t location;
  uint8_t additional_data[4];
} libspdm_data_parameter_t;

typedef uint32_t libspdm_session_id_t;

typedef struct libspdm_spdm_error_struct_t {
  uint8_t error_code;
  uint8_t error_data;
} libspdm_spdm_error_struct_t;

extern void printf(const int8_t *fmt);

extern int32_t fflush(void *stream);

libspdm_return_t libspdm_deinit_context(libspdm_context_t context);

libspdm_return_t libspdm_init_context(libspdm_context_t context);

libspdm_return_t libspdm_reset_context(libspdm_context_t context);

void libspdm_register_device_io_func(libspdm_context_t context,
                                     void *send_message,
                                     void *receive_message);

void libspdm_register_transport_layer_func(libspdm_context_t context,
                                           uint32_t max_msg_size,
                                           uint32_t transport_header_size,
                                           uint32_t transport_tail_size,
                                           void *transport_encode,
                                           void *transport_decode);

void libspdm_register_device_buffer_func(libspdm_context_t context,
                                         uint32_t sender_buffer_size,
                                         uint32_t receiver_buffer_size,
                                         void *acquire_sender,
                                         void *release_sender,
                                         void *acquire_receiver,
                                         void *release_receiver);

uintptr_t libspdm_get_sizeof_required_scratch_buffer(libspdm_context_t _context);

libspdm_return_t libspdm_set_scratch_buffer(libspdm_context_t context,
                                            uint8_t *scratch_buffer,
                                            uintptr_t scratch_buffer_size);

bool libspdm_check_context(libspdm_context_t context);

libspdm_return_t libspdm_set_data(libspdm_context_t context,
                                  uint32_t data_type,
                                  const struct libspdm_data_parameter_t *_parameter,
                                  const void *data,
                                  uintptr_t data_size);

libspdm_return_t libspdm_init_connection(libspdm_context_t context, bool get_version_only);

libspdm_return_t libspdm_get_data(libspdm_context_t context,
                                  uint32_t data_type,
                                  const struct libspdm_data_parameter_t *_parameter,
                                  void *data,
                                  uintptr_t *data_size);

libspdm_return_t libspdm_get_version(libspdm_context_t context,
                                     uint8_t *version_count,
                                     uint32_t *_version_number_entry);

libspdm_return_t libspdm_get_capabilities(libspdm_context_t _context);

libspdm_return_t libspdm_negotiate_algorithms(libspdm_context_t _context);

libspdm_return_t libspdm_get_digests(libspdm_context_t context,
                                     uint8_t *slot_mask,
                                     uint8_t *total_digest_buffer);

libspdm_return_t libspdm_get_certificate(libspdm_context_t context,
                                         const uint32_t *_session_id,
                                         uint8_t slot_id,
                                         uintptr_t *cert_chain_size,
                                         uint8_t *cert_chain);

libspdm_return_t libspdm_challenge(libspdm_context_t context,
                                   const void *_requester_context,
                                   uint8_t slot_id,
                                   uint8_t measurement_hash_type,
                                   uint8_t *measurement_hash,
                                   uint8_t *slot_mask);

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
                                     uint8_t _end_session_attributes);

libspdm_return_t libspdm_get_measurement_ex(libspdm_context_t context,
                                            libspdm_session_id_t session_id,
                                            uint8_t _request_attribute,
                                            uint8_t _measurement_operation,
                                            uint8_t _slot_id,
                                            uint8_t *_number_of_blocks,
                                            uint32_t *_measurement_record_length,
                                            uint8_t *_measurement_record);

uintptr_t libspdm_get_hash_size(uint32_t hash_algo);

libspdm_return_t libspdm_generate_nonce(libspdm_context_t context,
                                        uint8_t *nonce,
                                        uintptr_t nonce_size);

void libspdm_free_context(libspdm_context_t _context);

libspdm_return_t libspdm_secured_message_get_last_spdm_error_struct(libspdm_context_t context,
                                                                    libspdm_session_id_t session_id,
                                                                    struct libspdm_spdm_error_struct_t *last_spdm_error_struct);

libspdm_return_t libspdm_set_last_spdm_error_struct(libspdm_context_t context,
                                                    libspdm_session_id_t session_id,
                                                    const struct libspdm_spdm_error_struct_t *_last_spdm_error_struct);

void *libspdm_get_secured_message_context_via_session_id(libspdm_context_t context,
                                                         libspdm_session_id_t session_id);

libspdm_return_t libspdm_encode_secured_message(void *_secured_message_context,
                                                libspdm_session_id_t session_id,
                                                bool is_request_message,
                                                uintptr_t message_size,
                                                const uint8_t *message,
                                                uintptr_t *secured_message_size,
                                                uint8_t *secured_message);

libspdm_return_t libspdm_decode_secured_message(void *_secured_message_context,
                                                libspdm_session_id_t session_id,
                                                bool is_request_message,
                                                uintptr_t secured_message_size,
                                                const uint8_t *secured_message,
                                                uintptr_t *message_size,
                                                void **message);

bool libspdm_is_session_established(libspdm_context_t context, libspdm_session_id_t session_id);

void *libspdm_get_session_info(libspdm_context_t context, libspdm_session_id_t session_id);

void libspdm_register_get_response_func(libspdm_context_t context, void *_get_response_func);

void libspdm_register_verify_spdm_cert_chain_func(libspdm_context_t context, void *verify_func);

libspdm_return_t libspdm_start_session(libspdm_context_t context,
                                       bool use_psk,
                                       const void *_psk_hint,
                                       uint16_t _psk_hint_size,
                                       uint8_t measurement_hash_type,
                                       uint8_t slot_id,
                                       uint8_t session_policy,
                                       uint32_t *session_id,
                                       uint8_t *heartbeat_period,
                                       void *measurement_hash);

libspdm_return_t libspdm_stop_session(libspdm_context_t context,
                                      libspdm_session_id_t session_id,
                                      uint8_t _end_session_attributes);

libspdm_return_t libspdm_send_receive_data(libspdm_context_t context,
                                           const libspdm_session_id_t *session_id,
                                           bool _is_app_message,
                                           const uint8_t *request,
                                           uintptr_t request_size,
                                           uint8_t *response,
                                           uintptr_t *response_size);

/**
 * Stub for libspdm_get_random_number - just fills with deterministic value for testing
 */
bool libspdm_get_random_number(uintptr_t size, uint8_t *rand);

libspdm_return_t pci_ide_km_query(const void *_pci_doe_context,
                                  void *_spdm_context,
                                  const uint32_t *_session_id,
                                  uint8_t _port_index,
                                  uint8_t *_dev_func_num,
                                  uint8_t *_bus_num,
                                  uint8_t *_segment,
                                  uint8_t *_max_port_index,
                                  uint32_t *_ide_reg_buffer,
                                  uint32_t *_ide_reg_buffer_count);

libspdm_return_t pci_ide_km_key_prog(const void *_pci_doe_context,
                                     void *_spdm_context,
                                     const uint32_t *_session_id,
                                     uint8_t _stream_id,
                                     uint8_t _key_sub_stream,
                                     uint8_t _port_index,
                                     const void *_key_buffer,
                                     uint8_t *_kp_ack_status);

libspdm_return_t pci_ide_km_key_set_go(const void *_pci_doe_context,
                                       void *_spdm_context,
                                       const uint32_t *_session_id,
                                       uint8_t _stream_id,
                                       uint8_t _key_sub_stream,
                                       uint8_t _port_index);

libspdm_return_t pci_ide_km_key_set_stop(const void *_pci_doe_context,
                                         void *_spdm_context,
                                         const uint32_t *_session_id,
                                         uint8_t _stream_id,
                                         uint8_t _key_sub_stream,
                                         uint8_t _port_index);

libspdm_return_t pci_ide_km_send_receive_data(void *_spdm_context,
                                              const uint32_t *_session_id,
                                              const void *_request,
                                              uintptr_t _request_size,
                                              void *_response,
                                              uintptr_t *_response_size);

extern void printf(const int8_t *fmt);

libspdm_return_t pci_tdisp_get_version(const void *_pci_doe_context,
                                       void *spdm_context,
                                       const uint32_t *session_id,
                                       const void *interface_id);

libspdm_return_t pci_tdisp_get_capabilities(const void *_pci_doe_context,
                                            void *spdm_context,
                                            const uint32_t *session_id,
                                            const void *interface_id,
                                            const void *req_caps,
                                            void *rsp_caps);

libspdm_return_t pci_tdisp_lock_interface(const void *_pci_doe_context,
                                          void *spdm_context,
                                          const uint32_t *session_id,
                                          const void *interface_id,
                                          const void *lock_interface_param,
                                          uint8_t *start_interface_nonce);

libspdm_return_t pci_tdisp_get_interface_report(const void *_pci_doe_context,
                                                void *_spdm_context,
                                                const uint32_t *_session_id,
                                                const void *_interface_id,
                                                uint8_t *_interface_report,
                                                uint32_t *_interface_report_size);

libspdm_return_t pci_tdisp_get_interface_state(const void *_pci_doe_context,
                                               void *spdm_context,
                                               const uint32_t *session_id,
                                               const void *interface_id,
                                               uint8_t *tdi_state);

libspdm_return_t pci_tdisp_start_interface(const void *_pci_doe_context,
                                           void *spdm_context,
                                           const uint32_t *session_id,
                                           const void *interface_id,
                                           const uint8_t *start_interface_nonce);

libspdm_return_t pci_tdisp_stop_interface(const void *_pci_doe_context,
                                          void *spdm_context,
                                          const uint32_t *session_id,
                                          const void *interface_id);

libspdm_return_t pci_tdisp_send_receive_data(void *_spdm_context,
                                             const uint32_t *_session_id,
                                             const void *_request,
                                             uintptr_t _request_size,
                                             void *_response,
                                             uintptr_t *_response_size);

#endif /* RUST_SPDM_MINIMAL_H */
