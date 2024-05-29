#ifndef _ICHEER_CMD_H
#define _ICHEER_CMD_H
/*
* INCLUDES 
*/
#include <stdint.h>
#include "icheer_cmd_comm.h"

// #define AES_KEY		                            "5hvbam6kfbyctw5h"//yiwang "vtwhc3jovyzvd4h4"

// #define DEFAULT_DEVICE_CODE_STR					0x00,0x0A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x60,0x01,0x00


#define LENGTH_STATE_DESCRIPTION                3


#define BYTE_RESET                              4
#define BYTE_NUM                                5

#define BYTE_BATTERY                            8
#define BYTE_DEV_STATE                          9
#define BYTE_MODE_CNT                           10


#define CMD_SESSION_START                        0x00//起始段
#define CMD_SESSION_START_CONFIRM                0x00
#define CMD_READ_STATUS                          0x01//读取设备的状态
#define CMD_READ_STATUS_CONFIRM     	         0x01
#define CMD_SET_DEVICE_NAME                      0x02//设置设备名称
#define CMD_SET_DEVICE_NAME_CONFIRM     	     0x02
#define CMD_SET_DEVICE_PIN                       0x03//设置设备名称
#define CMD_SET_DEVICE_PIN_CONFIRM               0x03
#define CMD_KEY_AUTH                             0x04//正向认证
#define CMD_KEY_AUTH_CONFIRM                     0x04
#define CMD_REVERSE_KEY_AUTH                     0x05//反向认证
#define CMD_REVERSE_KEY_AUTH_CONFIRM             0x05
#define CMD_GET_VERSION                          0x06
#define CMD_GET_VERSION_CONFIRM                  0x06
#define CMD_SYNC_TIME                            0x07//同步设备时间 
#define CMD_SYNC_TIME_CONFIRM                    0x07
#define CMD_READ_DEV_CODE                        0x08
#define CMD_READ_DEV_CODE_CONFIRM                0x08
#define CMD_SET_MODE_PARAMS                      0x09
#define CMD_SET_MODE_PARAMS_CONFIRM              0x09
#define CMD_SET_STRENGTH                         0x0A
#define CMD_SET_STRENGTH_CONFIRM                 0x0A
#define CMD_SET_TIME_LEN                         0x0B
#define CMD_SET_TIME_LEN_CONFIRM                 0x0B
#define CMD_NOTIFY_MODE_PARAMS                   0x0C
#define CMD_NOTIFY_MODE_PARAMS_CONFIRM           0x0C
#define CMD_NOTIFY_STRENGTH                      0x0D
#define CMD_NOTIFY_STRENGTH_CONFIRM              0x0D
#define CMD_READ_MODE_PARAMS                     0x0E
#define CMD_READ_MODE_PARAMS_CONFIRM             0x0E
#define CMD_READ_STRENGTH                        0x0F
#define CMD_READ_STRENGTH_CONFIRM                0x0F
#define CMD_START                                0x10
#define CMD_START_CONFIRM                        0x10
#define CMD_PAUSE                                0x11
#define CMD_PAUSE_CONFIRM                        0x11
#define CMD_STOP                                 0x11
#define CMD_STOP_CONFIRM                         0x11
#define CMD_NOTIFY_START                         0x12
#define CMD_NOTIFY_START_CONFIRM                 0x12
#define CMD_NOTIFY_STOP                          0x13
#define CMD_NOTIFY_STOP_CONFIRM                  0x13
#define CMD_SET_DEFAULT_MODE_PARAMS              0x14
#define CMD_SET_DEFAULT_MODE_PARAMS_CONFIRM      0x14
#define CMD_READ_DEFAULT_MODE_PARAMS             0x15
#define CMD_READ_DEFAULT_MODE_PARAMS_CONFIRM     0x15
#define CMD_SHUTDOWN                             0x16
#define CMD_SHUTDOWN_CONFIRM                     0x16
#define CMD_NOTIFY_SHUTDOWN                      0x17
#define CMD_NOTIFY_SHUTDOWN_CONFIRM              0x17

#define CMD_SET_TEST_FLAG						0x20
#define CMD_SET_TEST_FLAG_CONFIRM				0x20
#define CMD_GET_TEST_FLAG						0x21
#define CMD_GET_TEST_FLAG_CONFIRM				0x21

#define CMD_SET_MULTI_MODE_PARAMS                0x40
#define CMD_SET_MULTI_MODE_PARAMS_CONFIRM        0x40

#define CMD_READ_DEFAULT_MODE_PARAM              0x41
#define CMD_READ_DEFAULT_MODE_CONFIRM            0x41

#define CMD_SET_TEMPERATURE_PARAM                0x42
#define CMD_SET_TEMPERATURE_PARAM_CONFIRM        0x42
#define CMD_SET_LOCK_PANEL                       0x43
#define CMD_SET_LOCK_PANEL_CONFIRM               0x43
#define CMD_NOTIFY_TEMPERATURE_PARAM             0x44
#define CMD_NOTIFY_TEMPERATURE_PARAM_CONFIRM     0x44
#define CMD_NOTIFY_READY                         0x45
#define CMD_NOTIFY_READY_CONFIRM                 0x45
#define CMD_NOTIFY_MODE_PARAM                    0x51


// void cmd_notify_ready();
// void cmd_notify_start();
// void cmd_notify_shutdown();

// void cmd_notify_mode();
// void cmd_notify_strength();
// void cmd_notify_temperature();

// void project_ble_cmd_init(void);


#endif
