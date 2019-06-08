
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <switch.h>

#include "gdb_stub.h"
#include "error.h"

#define BUFFER_SIZE 512u

typedef enum
{
    CMD_STATE_START,
    CMD_STATE_DATA,
    CMD_STATE_CHECKSUM,
} cmd_state_t;

struct gdb_stub
{
    gdb_stub_output_t output;
    void* arg;

    Handle session;

    char tx_buffer[BUFFER_SIZE];

    struct
    {
        cmd_state_t state;
        char buffer[BUFFER_SIZE];
        size_t pos;
        char checksum_buf[2];
        size_t checksum_pos;
        uint8_t checksum;
    } rx;
};

gdb_stub_t* gdb_stub_create(gdb_stub_output_t output, void* arg)
{
    gdb_stub_t* stub = calloc(1u, sizeof(*stub));
    if(stub == NULL)
    {
        goto err;
    }

    stub->output = output;
    stub->arg = arg;
    stub->rx.state = CMD_STATE_START;

    Result res = svcDebugActiveProcess(&stub->session, 0x84);
    if(R_FAILED(res))
    {
        printf("svcDebugActiveProcess failed (%d-%d)\n", R_MODULE(res), R_DESCRIPTION(res));
        goto err_1;
    }

    return stub;
err_1:
    free(stub);
err:
    return NULL;
}

static uint8_t gdb_stub_decode_hex_char(char c)
{
    if ((c >= 'a') && (c <= 'f'))
        return (c - 'a' + 10);
    if ((c >= '0') && (c <= '9'))
        return (c - '0');
    if ((c >= 'A') && (c <= 'F'))
        return (c - 'A' + 10);

    return UINT8_MAX;
}

static int gdb_stub_decode_hex(const char* input, size_t input_len, uint8_t* output, size_t output_len)
{
    int dec_len = 0;

    if((input_len & 1) != 0u || output_len < input_len / 2u)
    {
        return -1;
    }

    for(size_t i = 0u; i < input_len / 2u; ++i)
    {
        uint8_t high = gdb_stub_decode_hex_char(input[i*2]);
        uint8_t low = gdb_stub_decode_hex_char(input[(i*2)+1]);
        if(high > 0xFu || low > 0xFu)
        {
            return -1;
        }

        output[i] = (high << 4u) | low;
        dec_len++;
    }

    return dec_len;
}

static int gdb_stub_encode_hex(const uint8_t* data, size_t data_len, char* output, size_t output_len)
{
    static const char hex_chars[] = "0123456789abcdef";
    int enc_len = 0;

    if(output_len < data_len * 2u)
    {
        return -1;
    }

    for(uint32_t i = 0u; i < data_len; ++i)
    {
        *output++ = hex_chars[(data[i] >> 4u) & 0xFu];
        *output++ = hex_chars[data[i] & 0xFu];
        enc_len += 2;
    }

    return enc_len;
}

static void gdb_stub_putc(gdb_stub_t* stub, char c)
{
    stub->output(stub, &c, 1u, stub->arg);
}

static void gdb_stub_send_packet(gdb_stub_t* stub, char* packet)
{
    size_t pos = 0u;
    uint8_t checksum = 0u;

    stub->tx_buffer[pos++] = '$';

    while(pos < BUFFER_SIZE-1u && *packet != '\0')
    {
        char c = *packet;

        if(c == '$' || c == '#' || c == '}')
        {
            stub->tx_buffer[pos++] = '}';
            checksum += '}';
            c ^= 0x20;
        }

        stub->tx_buffer[pos++] = c;
        checksum += c;
        packet++;
    }

    if(*packet != '\0' || (BUFFER_SIZE - pos) < 3u)
    {
        // buffer is too small
        return;
    }

    stub->tx_buffer[pos++] = '#';
    gdb_stub_encode_hex(&checksum, sizeof(checksum),
            &stub->tx_buffer[pos], BUFFER_SIZE - pos);
    pos += 2u;

    stub->output(stub, stub->tx_buffer, pos, stub->arg);
}

static void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err)
{
    char packet[3];

    packet[0] = 'E';
    if(gdb_stub_encode_hex(&err, sizeof(err), &packet[1], 2) != 2)
    {
        return;
    }

    gdb_stub_send_packet(stub, packet);
}

static void gdb_stub_packet(gdb_stub_t* stub, char* packet)
{
    printf("gdb_stub: got packet (%s)\n", packet);

    switch(packet[0])
    {
    case 'g':
        // read registers
        break;
    case 'G':
        // write registers
        break;
    case 'p':
        // read register
        break;
    case 'P':
        // write register
        break;
    case 'm':
        // read memory
        break;
    case 'M':
        // write memory
        break;
    case 'X':
        // write memory binary
        break;
    case 'c':
        // continue
        break;
    case 's':
        // single step
        break;
    case '?':
        // get halt reason
        break;
    default:
        gdb_stub_send_packet(stub, "");
        break;
    }

    return;

error:
    gdb_stub_send_error(stub, 0);
}

static void gdb_stub_insert_char(gdb_stub_t* stub, char c)
{
    switch(stub->rx.state)
    {
    case CMD_STATE_START:
        if(c == '$')
        {
            stub->rx.state = CMD_STATE_DATA;
            stub->rx.pos = 0u;
            stub->rx.checksum = 0u;
        }
        break;
    case CMD_STATE_DATA:
        if(c == '$')
        {
            stub->rx.state = CMD_STATE_START;
        }
        else if(c == '#')
        {
            stub->rx.state = CMD_STATE_CHECKSUM;
            stub->rx.checksum_pos = 0u;
        }
        else if(stub->rx.pos < BUFFER_SIZE-1)
        {
            stub->rx.buffer[stub->rx.pos++] = c;
            stub->rx.checksum += (uint8_t)c;
        }
        else
        {
            // buffer too small
            stub->rx.state = CMD_STATE_START;
            gdb_stub_send_error(stub, 0);
        }
        break;
    case CMD_STATE_CHECKSUM:
        stub->rx.checksum_buf[stub->rx.checksum_pos++] = c;

        if(stub->rx.checksum_pos == 2u)
        {
            uint8_t checksum;
            if(gdb_stub_decode_hex(stub->rx.checksum_buf, 2u, &checksum, sizeof(checksum)) == 1
                    && checksum == stub->rx.checksum)
            {
                // null terminate the packet
                stub->rx.buffer[stub->rx.pos] = '\0';

                gdb_stub_putc(stub, '+');
                if(stub->rx.pos > 2u && stub->rx.buffer[2] == ':')
                {
                    gdb_stub_putc(stub, stub->rx.buffer[0]);
                    gdb_stub_putc(stub, stub->rx.buffer[1]);

                    gdb_stub_packet(stub, &stub->rx.buffer[3]);
                }
                else
                {
                    gdb_stub_packet(stub, stub->rx.buffer);
                }
            }
            else
            {
                printf("gdb_stub: bad checksum\n");
                gdb_stub_putc(stub, '-');
            }

            stub->rx.state = CMD_STATE_START;
        }
        break;
    }
}

void gdb_stub_input(gdb_stub_t* stub, char* buffer, size_t length)
{
    while(length != 0u)
    {
        gdb_stub_insert_char(stub, *buffer);
        buffer++;
        length--;
    }
}

void gdb_stub_destroy(gdb_stub_t* stub)
{
    memset(stub, 0, sizeof(*stub));
    free(stub);
}

Result gdb_stub_get_waiter(gdb_stub_t* stub, Waiter* waiter)
{
    if(stub->session != INVALID_HANDLE)
    {
        *waiter = waiterForHandle(stub->session);
        return 0;
    }

    return MAKERESULT(Module_SysGdbStub, SysGdbStubError_NoActiveSession);
}

void gdb_stub_handle_events(gdb_stub_t* stub)
{
    Result res;

    if(stub->session == INVALID_HANDLE)
    {
        return;
    }

#if 0
    res = waitSingleHandle(stub->session, 0u);
    if(R_SUCCEEDED(res))
    {
        u8 event;
        // debug event ready
        res = svcGetDebugEvent(&event, stub->session);
        if(R_SUCCEEDED(res))
        {
            printf("debug event: 0x%X\n", event);
        }
    }
#endif
}
