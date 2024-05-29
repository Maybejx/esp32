#ifndef _ICHEER_CMD_COMM_H
#define _ICHEER_CMD_COMM_H

#define DATA_PACKAGE_LEN						20
#define CMD_BUFFER_LEN							128
#define RECV_BUFFER_LEN							(CMD_BUFFER_LEN + 32)

#define LENGTH_SESSION                          4
#define CMD_HEADER_START                        0xEE

#define BYTE_START                              0 
#define BYTE_LENGTH_HI                          1
#define BYTE_LENGTH_LO                          2
#define BYTE_CMD                                3
#define BYTE_SESSION                            4

#define DATA_START                              4

#define LENGTH_REG                              1
#define LENGTH_CRC                              1
#define LENGTH_RESULT                           1
#define LENGTH_START                            1
#define LENGTH_LENGTH                           2
#define LENGTH_CMD                              1
#define LENGTH_HEAD                             (LENGTH_START + LENGTH_LENGTH + LENGTH_CMD)

// typedef void (*pCmdCallback)(uint8_t *, uint8_t);

// void recv_end_process(void);


// void usr_ble_cmd_init(void);
// void usr_ble_connection_init(void);
// void usr_ble_cmd_recv(uint8_t *p_data, uint16_t length);


// void icheer_ble_cmd_register(uint8_t cmd, pCmdCallback fn);

// void cmd_dump(uint8_t *p_data, uint8_t len, uint8_t dbg_on);

// uint8_t cmd_checksum(uint8_t *p_data, uint8_t length);

// void cmd_send(uint8_t *p_data, uint8_t length);

// void cmd_pack_and_send(uint8_t ble_cmd, uint8_t *p_data, uint8_t length);

#endif
