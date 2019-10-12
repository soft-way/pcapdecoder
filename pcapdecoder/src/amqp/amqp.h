
#ifndef __AMQP_H__
#define __AMQP_H__

#define AMQP_FRAME_TYPE_METHOD      1
#define AMQP_FRAME_TYPE_HEADER      2
#define AMQP_FRAME_TYPE_BODY        3
#define AMQP_FRAME_TYPE_HEARTBEAT   4
#define AMQP_PROTOCAL_HEADER        0x41

#define AMQP_MAX_CLASS   85
#define AMQP_MAX_METHOD  80

int parseAMQP(unsigned char* data, int len);
int parseAmqpBody(unsigned char* data, int len, int amqp_idx);
int parseAmqpHeader(unsigned char* data, int amqp_idx);
int parseAmqpMethod(unsigned char* data, int amqp_idx);

void class_amqp_basic(unsigned char* data, int c, int m, int amqp_idx);
void class_amqp_channel(unsigned char* data, int c, int m, int amqp_idx);
void class_amqp_confirm(unsigned char* data, int c, int m, int amqp_idx);
void class_amqp_connection(unsigned char* data, int c, int m, int amqp_idx);
void class_amqp_exchange(unsigned char* data, int c, int m, int amqp_idx);
void class_amqp_queue(unsigned char* data, int c, int m, int amqp_idx);

unsigned char* get_class_method(int c, int m);
void init_amqp_class_method();
int amqp_body_output(unsigned char* data, int len);

#endif // __AMQP_H__