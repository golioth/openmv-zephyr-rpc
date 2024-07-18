/*
 * Copyright (c) 2024 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * COMMAND HEADER
 *
 * FIELD || magic | command | payload_len | CRC16
 * ----- || ----- | ------- | ----------- | -----
 * SIZE  ||   2   |    4    |      4      |   2
 *
 */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(openmv_rpc, LOG_LEVEL_INF);

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/init.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/time_units.h>

#include <openmv_rpc.h>

#define OPENMV_RPC_COMMAND_HEADER_PACKET_MAGIC 0x1209
#define OPENMV_RPC_COMMAND_DATA_PACKET_MAGIC 0xABD1
#define OPENMV_RPC_RESULT_HEADER_PACKET_MAGIC 0x9021
#define OPENMV_RPC_RESULT_DATA_PACKET_MAGIC 0x1DBA
#define OPENMV_RPC_STREAM_READER_PACKET_MAGIC 0xEDF6
#define OPENMV_RPC_STREAM_WRITER_PACKET_MAGIC 0x542E

#define OPENMV_RPC_CRC16_POLY 0x1021
#define OPENMV_RPC_CRC16_SEED 0xFFFF

struct openmv_rpc_empty_packet
{
    uint16_t magic;
    uint16_t crc16;
} __attribute__((packed));

struct openmv_rpc_command_header
{
    uint16_t magic;
    uint32_t command_hash;
    uint32_t payload_len;
    uint16_t crc16;
} __attribute__((packed));

struct openmv_rpc_result_header_ack
{
    uint16_t magic;
    uint32_t payload_len;
    uint16_t crc16;
} __attribute__((packed));

enum openmv_result_rx_state
{
    OPENMV_RESULT_IDLE,
    OPENMV_RESULT_WAITING_FOR_MAGIC,
    OPENMV_RESULT_WAITING_FOR_PAYLOAD,
    OPENMV_RESULT_WAITING_FOR_CRC
};

/* Result payload is received in multiple parts to support user-provided,
   variable-length buffers */
struct openmv_result_data_packet
{
    uint16_t magic;
    uint16_t crc16;
    enum openmv_result_rx_state state;
    size_t payload_len;
    void *payload;
};

static const struct device *const rpc_uart_dev = DEVICE_DT_GET(DT_CHOSEN(openmv_rpc_uart));
static struct openmv_result_data_packet result_data;

struct k_poll_signal uart_rx_sig;
struct k_poll_signal uart_tx_sig;

/* Note: OpenMV RPC uses the XOR variation of djb2 */
static uint32_t djb2(const void *data, size_t len)
{
    uint32_t hash = 5381;
    for (int i = 0; i < len; i++)
    {
        hash = hash * 33 ^ ((uint8_t *) data)[i];
    }

    return hash;
}

static struct openmv_rpc_empty_packet openmv_rpc_basic_packet(uint16_t magic)
{
    struct openmv_rpc_empty_packet pkt = {
        .magic = magic,
    };
    pkt.crc16 = crc16(OPENMV_RPC_CRC16_POLY,
                      OPENMV_RPC_CRC16_SEED,
                      (uint8_t *) &pkt,
                      sizeof(pkt) - sizeof(pkt.crc16));

    return pkt;
}

static void flush_uart(void)
{
    char c;
    while (0 == uart_poll_in(rpc_uart_dev, &c))
    {
    }
}

static void openmv_rpc_tx(const void *data, size_t len)
{
    struct k_poll_event done =
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY, &uart_tx_sig);
    k_poll_signal_reset(&uart_tx_sig);

    uart_tx(rpc_uart_dev, data, len, SYS_FOREVER_US);

    k_poll(&done, 1, K_FOREVER);
}

static void openmv_rpc_tranceive(const void *tx_buf,
                                 size_t tx_buf_len,
                                 void *rx_buf,
                                 size_t rx_buf_len)
{
    flush_uart();
    k_poll_signal_reset(&uart_rx_sig);

    uart_rx_enable(rpc_uart_dev, rx_buf, rx_buf_len, 100000);

    uart_tx(rpc_uart_dev, tx_buf, tx_buf_len, SYS_FOREVER_US);

    struct k_poll_event done =
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY, &uart_rx_sig);

    int err = k_poll(&done, 1, K_MSEC(5));

    uart_rx_disable(rpc_uart_dev);

    if (-EAGAIN == err)
    {
        LOG_WRN("Read timedout");
    }
    else if (uart_rx_sig.result != 0)
    {
        LOG_ERR("Received UART rx event %d", uart_rx_sig.result);
    }
}

static bool openmv_rpc_send_with_basic_ack(const void *tx_buf,
                                           size_t tx_buf_len,
                                           uint16_t ack_value)
{
    struct openmv_rpc_empty_packet ack = {0};

    openmv_rpc_tranceive(tx_buf, tx_buf_len, &ack, sizeof(ack));

    uint16_t calculated_crc = crc16(OPENMV_RPC_CRC16_POLY,
                                    OPENMV_RPC_CRC16_SEED,
                                    (uint8_t *) &ack,
                                    sizeof(ack) - sizeof(ack.crc16));

    if (calculated_crc != ack.crc16)
    {
        return false;
    }

    if (ack.magic != ack_value)
    {
        return false;
    }

    return true;
}

static int openmv_rpc_send_command(const char *command, const void *payload, size_t payload_len)
{
    /* Create Command Header packet */

    struct openmv_rpc_command_header pkt = {
        .magic = OPENMV_RPC_COMMAND_HEADER_PACKET_MAGIC,
        .payload_len = payload_len,
    };

    /* Calculate hash of command name */

    pkt.command_hash = djb2(command, strlen(command));

    /* Calculate CRC16 */

    pkt.crc16 = crc16(OPENMV_RPC_CRC16_POLY,
                      OPENMV_RPC_CRC16_SEED,
                      (uint8_t *) &pkt,
                      sizeof(pkt) - sizeof(pkt.crc16));

    /* Write Command Header packet and wait for ack */

    openmv_rpc_send_with_basic_ack(&pkt, sizeof(pkt), OPENMV_RPC_COMMAND_HEADER_PACKET_MAGIC);

    /* Write Command Data packet magic */

    uint16_t data_packet_magic = OPENMV_RPC_COMMAND_DATA_PACKET_MAGIC;
    openmv_rpc_tx(&data_packet_magic, sizeof(data_packet_magic));

    /* Write payload */

    if (payload_len > 0)
    {
        openmv_rpc_tx(payload, payload_len);
    }

    /* Calculate and write CRC16 and wait for ack */

    uint16_t data_pkt_crc16 = crc16(OPENMV_RPC_CRC16_POLY,
                                    OPENMV_RPC_CRC16_SEED,
                                    (uint8_t *) &data_packet_magic,
                                    sizeof(data_packet_magic));
    data_pkt_crc16 = crc16(OPENMV_RPC_CRC16_POLY, data_pkt_crc16, payload, payload_len);

    openmv_rpc_send_with_basic_ack(&data_pkt_crc16,
                                   sizeof(data_pkt_crc16),
                                   OPENMV_RPC_COMMAND_DATA_PACKET_MAGIC);

    return 0;
}

static int openmv_rpc_get_result(void *buf, size_t buf_len)
{
    /* Send Result Header and wait for ack with result payload length */

    struct openmv_rpc_empty_packet result_header =
        openmv_rpc_basic_packet(OPENMV_RPC_RESULT_HEADER_PACKET_MAGIC);
    struct openmv_rpc_result_header_ack result_ack = {0};

    openmv_rpc_tranceive(&result_header, sizeof(result_header), &result_ack, sizeof(result_ack));

    if (result_ack.payload_len > buf_len)
    {
        LOG_ERR("Result buffer is too small (%d > %d)", result_ack.payload_len, buf_len);
        return -EFBIG;
    }

    /* Send Result Data packet and wait for response payload. The response is received
       in multiple parts (magic, payload, CRC), in order to support a user provided
       payload buffer. */

    struct openmv_rpc_empty_packet result_data_request =
        openmv_rpc_basic_packet(OPENMV_RPC_RESULT_DATA_PACKET_MAGIC);

    result_data.magic = 0;
    result_data.crc16 = 0;
    result_data.payload = buf;
    result_data.payload_len = result_ack.payload_len;
    result_data.state = OPENMV_RESULT_WAITING_FOR_MAGIC;

    openmv_rpc_tranceive(&result_data_request,
                         sizeof(result_data_request),
                         &result_data.magic,
                         sizeof(result_data.magic));

    /* Ensure the state is reset in case of error */

    result_data.state = OPENMV_RESULT_IDLE;

    return 0;
}

int openmv_rpc_call(const char *command,
                    const void *command_payload,
                    size_t command_payload_len,
                    void *result_payload,
                    size_t result_payload_len)
{
    openmv_rpc_send_command(command, command_payload, command_payload_len);

    openmv_rpc_get_result(result_payload, result_payload_len);

    return 0;
}

static void uart_callback(const struct device *dev, struct uart_event *evt, void *unused)
{
    (void) unused;

    switch (evt->type)
    {
        case UART_RX_DISABLED:
            k_poll_signal_raise(&uart_rx_sig, 0);
            break;
        case UART_RX_STOPPED:
            k_poll_signal_raise(&uart_rx_sig, evt->data.rx_stop.reason);
            break;
        case UART_RX_BUF_REQUEST:
            /* If we are in the process of receiving result data,
               then provide the next buffer */
            switch (result_data.state)
            {
                case OPENMV_RESULT_WAITING_FOR_MAGIC:
                    uart_rx_buf_rsp(rpc_uart_dev, result_data.payload, result_data.payload_len);
                    result_data.state = OPENMV_RESULT_WAITING_FOR_PAYLOAD;
                    break;
                case OPENMV_RESULT_WAITING_FOR_PAYLOAD:
                    uart_rx_buf_rsp(rpc_uart_dev,
                                    (uint8_t *) &result_data.crc16,
                                    sizeof(result_data.crc16));
                    result_data.state = OPENMV_RESULT_WAITING_FOR_CRC;
                    break;
                case OPENMV_RESULT_WAITING_FOR_CRC:
                    result_data.state = OPENMV_RESULT_IDLE;
                    break;
                default:
                    break;
            }
            break;
        case UART_TX_DONE:
            k_poll_signal_raise(&uart_tx_sig, 0);
            break;
        default:
            break;
    }
}

static int openmv_rpc_init(void)
{
    k_poll_signal_init(&uart_rx_sig);
    k_poll_signal_init(&uart_tx_sig);

    uart_callback_set(rpc_uart_dev, uart_callback, NULL);

    return 0;
}

SYS_INIT(openmv_rpc_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);