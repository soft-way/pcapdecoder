
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "amqp.h"
#include "tcpip.h"

extern UINT32 eth_num;
extern UINT32 trace_level;
extern unsigned char time_str[128];
extern UINT32 net_byte_swap;

int channel;
int class;
int method;
int ticket;

unsigned char exchange[256];
unsigned char routing_key[256];
int amqp_num = 0;

unsigned char* class_method[AMQP_MAX_CLASS + 1][AMQP_MAX_METHOD + 1];
int class_method_ready = 0;

int parseAMQP(unsigned char* start, int len) {
    if (!class_method_ready) {
        init_amqp_class_method();
        class_method_ready = 1;
    }
    int amqp = 0;

    int idx = 0;
    int processed_len = 0;
    unsigned char* ptr = start;
    INFO("PDU is AMQP\n");
    while (idx < len) {
        ptr += processed_len;
        int type = *ptr;
        switch (*ptr) {
        case AMQP_FRAME_TYPE_METHOD:
            processed_len = parseAmqpMethod(ptr, amqp);
            break;
        case AMQP_FRAME_TYPE_HEADER:
            processed_len = parseAmqpHeader(ptr, amqp);
            break;
        case AMQP_FRAME_TYPE_BODY:
            processed_len = parseAmqpBody(ptr, len - (ptr-start), amqp);
            break;
        case 8:
        case AMQP_FRAME_TYPE_HEARTBEAT:
            INFO("AMQP(%d) heartbeat\n", amqp++);
            processed_len = 8;
            break;
        case AMQP_PROTOCAL_HEADER:
            if (memcmp(ptr, "AMQP", 4) == 0) {
                INFO("AMQP(%d) Protocal Header %c-%c-%c-%c\n", amqp,
                     '0' + *(ptr + 4), '0' + *(ptr + 5), '0' + *(ptr + 6), '0' + *(ptr + 7));
            } else {
                ERR("AMQP(%d) not supported AMQP protocal header (%d), ethernet package %d\n", amqp, type, eth_num);
                exit(1);
            }
            processed_len = 8;
            break;
        default:
            ERR("AMQP(%d) not supported frame type (%d), ethernet package %d\n", amqp, type, eth_num);
            return 0;
            //exit(2);
        };

        amqp++;
        idx += processed_len;
    }

    return amqp;
}

int parseAmqpMethod(unsigned char* data, int amqp_idx) {
    int type = *data;

    data++;
    channel = get_int16(data, net_byte_swap);

    data += 2;
    int length = get_int32(data, net_byte_swap);

    data += 4;
    class = get_int16(data, net_byte_swap);

    data += 2;
    method = get_int16(data, net_byte_swap);

    switch (class) {
    case 10: // Connection
        class_amqp_connection(data, class, method, amqp_idx);
        break;

    case 20: // Channel
        class_amqp_channel(data, class, method, amqp_idx);
        break;

    case 40: // Exchange
        class_amqp_exchange(data, class, method, amqp_idx);
        break;

    case 50: // Queue
        class_amqp_queue(data, class, method, amqp_idx);
        break;

    case 60: // Basic
        class_amqp_basic(data, class, method, amqp_idx);
        break;

    case 85: // Confirm
        class_amqp_confirm(data, class, method, amqp_idx);
        break;

    default:
        ERR("Unsupported class %d\n", class);
        exit(3);
    }

    DEBUG("AMQP(%d) method frame, type %d, channel %d, length %d, %s, exchange: %s, routing-key: %s\n",
          amqp_idx, type, channel, length, get_class_method(class, method), exchange, routing_key);

    return length + 8;
}

int parseAmqpHeader(unsigned char* data, int amqp_idx) {
    int type = *data;
    int channel = get_int16(data + 1, net_byte_swap);
    int length = get_int32(data + 3, net_byte_swap);
    int class = get_int16(data + 7, net_byte_swap);
    int weigth = get_int16(data + 9, net_byte_swap);
    UINT64 body_size = get_int64(data + 11, net_byte_swap);
    DEBUG("AMQP(%d) content header, type %d, channel %d, length %d, class %d, weigth: %d\n",
          amqp_idx, type, channel, length, class, weigth);

    return length + 8;
}

int parseAmqpBody(unsigned char* data, int len, int amqp_idx) {
    int type = *data;
    int channel = get_int16(data + 1, net_byte_swap);
    int length = get_int32(data + 3, net_byte_swap);
    unsigned char* payload = data + 7;
    DEBUG("AMQP(%d) content body, channel %d, length: %d\n", amqp_idx, channel, length);

    if (length > (len-7)) { // content body header 7 bytes
        INFO("Part of PDU data in next tcp package\n");

        unsigned char* ptr = malloc(len);
        if (ptr == 0) {
            ERR("Could not get memory %d\n", len);
            exit(4);
        }
        memcpy(ptr, data, len);
        add_tcp_data(ptr, len);

        return len;
    }

    amqp_body_output(data + 7, length);

    return length + 8;
}

void class_amqp_basic(unsigned char* data, int c, int m, int amqp_idx) {
    int exchange_len = 0;
    int routing_key_len = 0;

    switch (m) {
    case 20:
    case 21:
    case 80:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    case 40:
        data += 2;
        ticket = get_int16(data, net_byte_swap);

        data += 2;
        exchange_len = *data;

        data++;
        memcpy(exchange, data, exchange_len);
        exchange[exchange_len] = '\0';

        data += exchange_len;
        routing_key_len = *data;
        data++;
        memcpy(routing_key, data, routing_key_len);
        routing_key[routing_key_len] = '\0';
        break;

    case 60:
        data += 13;

        exchange_len = *data;
        data++;
        memcpy(exchange, data, exchange_len);
        exchange[exchange_len] = '\0';

        data += exchange_len;
        routing_key_len = *data;
        data++;
        memcpy(routing_key, data, routing_key_len);
        routing_key[routing_key_len] = '\0';
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(5);
    }
}

void class_amqp_channel(unsigned char* data, int c, int m, int amqp_idx) {
    switch (m) {
    case 10:
    case 11:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(6);
    }
}

void class_amqp_confirm(unsigned char* data, int c, int m, int amqp_idx) {
    switch (m) {
    case 10:
    case 11:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(7);
    }

}

void class_amqp_exchange(unsigned char* data, int c, int m, int amqp_idx) {
    switch (m) {
    case 10:
    case 11:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(8);
    }

}

void class_amqp_queue(unsigned char* data, int c, int m, int amqp_idx) {
    switch (m) {
    case 10:
    case 11:
    case 20:
    case 21:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(9);
    }

}

void class_amqp_connection(unsigned char* data, int c, int m, int amqp_idx) {
    switch (m) {
    case 10:
    case 11:
    case 30:
    case 31:
    case 40:
    case 41:
        INFO("AMQP(%d) %s\n", amqp_idx, get_class_method(c, m));
        break;

    default:
        ERR("Unsupported method %d for class %d\n", m, c);
        exit(10);
    }
}

unsigned char* get_class_method(int c, int m) {
    if (c > AMQP_MAX_CLASS) {
        ERR("Unsupported class %d\n", c);
        exit(11);
    }

    if (m > AMQP_MAX_METHOD) {
        ERR("Unsupported method %d\n", m);
        exit(12);
    }

    if (class_method[c][m] == 0) {
        ERR("Unsupported class %d, method %d\n", c, m);
        exit(13);
    }

    return class_method[c][m];
}

void init_amqp_class_method() {
    memset(class_method, 0, sizeof(class_method));

    class_method[10][10] = "Connection.Start";
    class_method[10][11] = "Connection.Start-Ok";
    class_method[10][30] = "Connection.Tune";
    class_method[10][31] = "Connection.Tune-Ok";
    class_method[10][40] = "Connection.Open";
    class_method[10][41] = "Connection.Open-Ok";

    class_method[20][10] = "Channel.Open";
    class_method[20][11] = "Channel.Open-Ok";

    class_method[40][10] = "Exchange.Declare";
    class_method[40][11] = "Exchange.Declare-Ok";

    class_method[50][10] = "Queu.Declare";
    class_method[50][11] = "Queu.Declare-Ok";
    class_method[50][20] = "Queu.Bind";
    class_method[50][21] = "Queu.Bind-Ok";

    class_method[60][20] = "Basic.Consume";
    class_method[60][21] = "Basic.Consume-Ok";
    class_method[60][40] = "Basic.Publish";
    class_method[60][60] = "Basic.Deliver";
    class_method[60][80] = "Basic.Ack";

    class_method[85][10] = "Confirm.Select";
    class_method[85][11] = "Confirm.Select-Ok";
}

int amqp_body_output(unsigned char* data, int len) {
    char filename[512];
    amqp_num++;

    sprintf(filename, "%s___%s_%05d-%s-%05d___AMQP%04d-ETH%04d___%s-x.%s-rk.%s.json",
            time_str, src_ip, src_port, dest_ip, dest_port, amqp_num, eth_num,
            get_class_method(class, method), *exchange ? (const char*)exchange : "null",
            *routing_key ? (const char*)routing_key : "null");
    FILE* out = fopen(filename, "wb");
    if (out == NULL) {
        ERR("Could not open file %s, err(%d): %s\n", filename, errno, strerror(errno));
        exit(14);
    }
    DEBUG("Writing to file: %s\n", filename);

    fwrite(data, 1, len, out);
    fclose(out);

    return len;
}
