/*
 * Copyright (c) 2024 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


int openmv_rpc_call(const char *command,
                    const void *command_payload,
                    size_t command_payload_len,
                    void *result_payload,
                    size_t result_payload_len,
                    k_timeout_t timeout);
int openmv_rpc_send_stream(const char *method);
int openmv_rpc_receive_stream(void);