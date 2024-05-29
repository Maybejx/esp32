/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

/****************************************************************************
*
* This demo showcases BLE GATT server. It can send adv data, be connected by client.
* Run the gatt_client demo, the client demo will automatically connect to the gatt_server demo.
* Client demo will enable gatt_server's notify after connection. The two devices will then exchange
* data.
*
****************************************************************************/
#include <sys/param.h>
#include <ctype.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif

#include "esp_http_client.h"
#include "cJSON.h"
#include "time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "icheer_aes.h"
#include "icheer_cmd_comm.h"
#include "icheer_cmd.h"
#include "sdkconfig.h"
#include "esp_mac.h"
#include "md5.h"

#define GATTS_TAG "GATTS_DEMO"
static const char *TAG = "HTTP_CLIENT";
#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 512//2048

extern const char howsmyssl_com_root_cert_pem_start[] asm("_binary_howsmyssl_com_root_cert_pem_start");
extern const char howsmyssl_com_root_cert_pem_end[]   asm("_binary_howsmyssl_com_root_cert_pem_end");

extern const char postman_root_cert_pem_start[] asm("_binary_postman_root_cert_pem_start");
extern const char postman_root_cert_pem_end[]   asm("_binary_postman_root_cert_pem_end");

///Declare the static function
static void gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);
static void gatts_profile_b_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

// #define GATTS_SERVICE_UUID_TEST_A   0x00FF
static uint8_t GATTS_SERVICE_UUID_TEST_A[16] = {
    0xe9, 0x7b, 0xe9, 0xa8, 0xf9, 0xc3, 0x8e, 0x96, 0x09, 0x4b, 0x10, 0xfa, 0x9c, 0xf3, 0x55, 0xa3
};
// #define GATTS_CHAR_UUID_TEST_A      0xFF01
static uint8_t GATTS_CHAR_UUID_TEST_A[16] = {
    0x7b, 0xfa, 0x8e, 0xc1, 0xa7, 0x4f, 0xaf, 0x8f, 0x30, 0x44, 0x55, 0xd5, 0x60, 0x22, 0x0f, 0x9b
};
#define GATTS_DESCR_UUID_TEST_A     0x3333
#define GATTS_NUM_HANDLE_TEST_A     4

#define GATTS_SERVICE_UUID_TEST_B   0x00EE
#define GATTS_CHAR_UUID_TEST_B      0xEE01
#define GATTS_DESCR_UUID_TEST_B     0x2222
#define GATTS_NUM_HANDLE_TEST_B     4

#define TEST_DEVICE_NAME            "iot-ESP32"
#define TEST_MANUFACTURER_DATA_LEN  17

#define GATTS_DEMO_CHAR_VAL_LEN_MAX 0x40

#define PREPARE_BUF_MAX_SIZE 1024

#define AES_KEY "05DO7gIc567YYlaZ"
#define keyCode_len 100
uint8_t session_key[LENGTH_SESSION];
static uint32_t send_num;
static uint8_t receive_data[128];
static uint16_t receive_len;
static uint8_t Device_Status;
static uint8_t wifi_ssid[32] = "\0";
static uint8_t wifi_password[32] = "\0";
char *sendData = NULL;
char return_secretKey[50]= {'\0'};
char secretKey[50]= {'\0'};
char deviceCode[] = "10000028";
uint64_t timestamp = 88888888;
char timestamp_string[50]= {'\0'};
char keyCode[keyCode_len] = {'\0'};
unsigned char keyCode_charge[keyCode_len]={'\0'};
char response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
int battery = 88;
char battery_string[6]= {'\0'};
int paper =77;
char paper_string[6]= {'\0'};
int liquid = 66;
char liquid_string[6]= {'\0'};
TimerHandle_t device_heartbeat,device_data,receive_data_process,wifi_reconnect,wifi_periodic_detection;
cJSON *pRoot;                         // JSON根部结构体
cJSON *pValue;                        // JSON子叶结构体

static uint8_t char1_str[] = {0x11,0x22,0x33};
static esp_gatt_char_prop_t a_property = 0;
static esp_gatt_char_prop_t b_property = 0;

static esp_attr_value_t gatts_demo_char1_val =
{
    .attr_max_len = GATTS_DEMO_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(char1_str),
    .attr_value   = char1_str,
};

static uint8_t adv_config_done = 0;
#define adv_config_flag      (1 << 0)
#define scan_rsp_config_flag (1 << 1)

#ifdef CONFIG_SET_RAW_ADV_DATA
static uint8_t raw_adv_data[] = {
        0x02, 0x01, 0x06,                  // Length 2, Data Type 1 (Flags), Data 1 (LE General Discoverable Mode, BR/EDR Not Supported)
        0x02, 0x0a, 0xeb,                  // Length 2, Data Type 10 (TX power leve), Data 2 (-21)
        0x03, 0x03, 0xab, 0xcd,            // Length 3, Data Type 3 (Complete 16-bit Service UUIDs), Data 3 (UUID)
};
static uint8_t raw_scan_rsp_data[] = {     // Length 15, Data Type 9 (Complete Local Name), Data 1 (ESP_GATTS_DEMO)
        0x0f, 0x09, 0x45, 0x53, 0x50, 0x5f, 0x47, 0x41, 0x54, 0x54, 0x53, 0x5f, 0x44,
        0x45, 0x4d, 0x4f
};
#else


static uint8_t adv_service_uuid128[32] = {
    /* LSB <--------------------------------------------------------------------------------> MSB */
    //first uuid, 16bit, [12],[13] is the value
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xEE, 0x00, 0x00, 0x00,
    //second uuid, 32bit, [12], [13], [14], [15] is the value
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
};

// The length of adv data must be less than 31 bytes
//static uint8_t test_manufacturer[TEST_MANUFACTURER_DATA_LEN] =  {0x12, 0x23, 0x45, 0x56};
//adv data
static esp_ble_adv_data_t adv_data = {
    .set_scan_rsp = false,
    .include_name = true,
    .include_txpower = false,
    .min_interval = 0x0006, //slave connection min interval, Time = min_interval * 1.25 msec
    .max_interval = 0x0010, //slave connection max interval, Time = max_interval * 1.25 msec
    .appearance = 0x00,
    .manufacturer_len = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data =  NULL, //&test_manufacturer[0],
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(adv_service_uuid128),
    .p_service_uuid = adv_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
// scan response data
static esp_ble_adv_data_t scan_rsp_data = {
    .set_scan_rsp = true,
    .include_name = true,
    .include_txpower = true,
    //.min_interval = 0x0006,
    //.max_interval = 0x0010,
    .appearance = 0x00,
    .manufacturer_len = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data =  NULL, //&test_manufacturer[0],
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(adv_service_uuid128),
    .p_service_uuid = adv_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

#endif /* CONFIG_SET_RAW_ADV_DATA */

static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    //.peer_addr            =
    //.peer_addr_type       =
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

#define PROFILE_NUM 2
#define PROFILE_A_APP_ID 0
#define PROFILE_B_APP_ID 1

struct gatts_profile_inst {
    esp_gatts_cb_t gatts_cb;
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
};

/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst gl_profile_tab[PROFILE_NUM] = {
    [PROFILE_A_APP_ID] = {
        .gatts_cb = gatts_profile_a_event_handler,
        .gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
    },
    [PROFILE_B_APP_ID] = {
        .gatts_cb = gatts_profile_b_event_handler,                   /* This demo does not implement, similar as profile A */
        .gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
    },
};

typedef struct {
    uint8_t                 *prepare_buf;
    int                     prepare_len;
} prepare_type_env_t;

static prepare_type_env_t a_prepare_write_env;
static prepare_type_env_t b_prepare_write_env;

void example_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);
void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);

void esp_cmd_send(uint8_t arr[],uint16_t len)
{
    // esp_gatt_rsp_t rsp;
    uint8_t Gatt_AES_value[ESP_GATT_MAX_ATTR_LEN] = {0};
    // uint8_t k;

    send_num++;
    // memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
    // rsp.attr_value.handle = 42;
    // rsp.attr_value.len = len;
    // memcpy(rsp.attr_value.value,arr,sizeof(arr)/sizeof(arr[0]));
    // len = aesECB128Encrypt(rsp.attr_value.value,Gatt_AES_value,(uint8*)AES_KEY,rsp.attr_value.len);

    len = aesECB128Encrypt(arr,Gatt_AES_value,(uint8*)AES_KEY,len);
    // memcpy(rsp.attr_value.value,Gatt_AES_value,sizeof(Gatt_AES_value)/sizeof(Gatt_AES_value[0]));
    esp_ble_gatts_send_indicate(3, 0, gl_profile_tab[PROFILE_A_APP_ID].char_handle,
                                                len, Gatt_AES_value, false);
    // esp_ble_gatts_send_response(3, 0, send_num,ESP_GATT_OK, &rsp);
}

uint8_t cmd_checksum(uint8_t *p_data, uint8_t length)
{
    uint8_t i, cs;

    cs = 0;

    for(i=0; i<length; i++)
    {
        cs += p_data[i];
    }

    return cs;
}

void cmd_pack_and_send(uint8_t ble_cmd, uint16_t cmd_direction, uint8_t *p_data, uint8_t length)
{
	uint8_t cmd_buffer[CMD_BUFFER_LEN];
    uint8_t cmd_length;

    //start byte + length + command + sesseion key + checksum
    cmd_length                  = LENGTH_HEAD + LENGTH_SESSION + length + LENGTH_CRC;
    cmd_buffer[BYTE_START]      = CMD_HEADER_START;
    cmd_buffer[BYTE_LENGTH_HI]  = cmd_direction >> 8;
    cmd_buffer[BYTE_LENGTH_LO]  = cmd_direction & 0xff;
    cmd_buffer[BYTE_CMD]        = ble_cmd;

    memcpy((uint8_t *)(&cmd_buffer[BYTE_SESSION]), session_key, LENGTH_SESSION);
	
	if((p_data != NULL) && (length > 0))
	{
    	memcpy((uint8_t *)(&cmd_buffer[LENGTH_HEAD + LENGTH_SESSION]), p_data, length);
	}
	
    cmd_buffer[cmd_length - 1] = cmd_checksum(cmd_buffer, cmd_length - 1);

    esp_cmd_send(cmd_buffer, cmd_length);
}

static void Read_Status_Send(void)
{
    cmd_pack_and_send(CMD_READ_STATUS,0x000a,&Device_Status,1);
}

static void Notify_Mode_Param_Send(void)
{
    cmd_pack_and_send(CMD_NOTIFY_MODE_PARAM,0x000a,&Device_Status,1);
}

static void Decompress_wifi(uint8_t *arr,uint16_t len)
{
    for(uint8_t j = 0;j<len-1;j++)
    {
        if((arr[j] == 0x2a) && (arr[j+1] == 0x2a))
        {
            if((j-9 >0)&&(len-j-3>0))
            {
                memset(wifi_ssid,'\0',32);
                memset(wifi_password,'\0',32);
                memcpy(wifi_ssid,&arr[9],j-9);
                memcpy(wifi_password,&arr[j+2],len-j-3);
                get_wifi_ssid_password(wifi_ssid,wifi_password);
                // printf("\nwifi_ssid = ");
                // for(uint8_t q =0;q<32;q++)
                // {
                //     printf("%x ",wifi_ssid[q]);
                // }
                // printf("\nwifi_password = ");
                // for(uint8_t q =0;q<32;q++)
                // {
                //     printf("%x ",wifi_password[q]);
                // }
            }
            else
            {
                printf("\nwifi error\n");
            }
        }
    }
}

static void receive_process(TimerHandle_t xTimer)
{
    static uint8_t real_data[128];
    static uint16_t real_len;
    uint8_t Decrypt_data[128];
#if 1
    if(receive_len>2)
    {
        // if(receive_len>0)
        // {
        //     printf("\nreceive_len = %d\n",receive_len);
        //     printf("\nreceive_data = ");
        //     for(uint8_t k =0;k<receive_len;k++)
        //     {
        //         printf("%x ",receive_data[k]);
        //     }
        // }

        memcpy(&real_data[real_len],receive_data,receive_len);
        real_len+=receive_len;
        if((real_len > 0) && (real_len % 16 == 0))
        {
            // printf("\nreal_len = %d\n",real_len);
            // printf("\nreal_data = ");
            // for(uint8_t k =0;k<real_len;k++)
            // {
            //     printf("%x ",real_data[k]);
            // }
            real_len = aesECB128Decrypt(real_data,Decrypt_data,(uint8*)AES_KEY,real_len);
            // printf("\nDecrypt_len = %d\n",real_len);
            // printf("\nDecrypt_data = ");
            // for(uint8_t k =0;k<real_len;k++)
            // {
            //     printf("%x ",Decrypt_data[k]);
            // }
            if(Decrypt_data[3] == 0x01)
            {
                Read_Status_Send();
            }
            else if(Decrypt_data[3] == 0x50)
            {
                Decompress_wifi(Decrypt_data,real_len);
    
            }
            else if(Decrypt_data[3] == 0x00)
            {
                cmd_pack_and_send(CMD_SESSION_START,0x0009,NULL,0);
            }
            else
            {
                printf("\nUnknown Cmd\n");
            }
            real_len = 0;
            memset(real_data,0,64);
            memset(receive_data,0,64);
        }
    }
    receive_len = 0;
#else
    if(receive_len>0)
        {
            printf("\nreceive_len = %d\n",receive_len);
            printf("\nreceive_data = ");
            for(uint8_t k =0;k<receive_len;k++)
            {
                printf("%x ",receive_data[k]);
            }
        }

    memcpy(&real_data[real_len],receive_data,receive_len);
    real_len+=receive_len;
    if((real_len > 0) && (real_len % 16 == 0))
    {
        // printf("\nreal_len = %d\n",real_len);
        // printf("\nreal_data = ");
        // for(uint8_t k =0;k<real_len;k++)
        // {
        //     printf("%x ",real_data[k]);
        // }
        real_len = aesECB128Decrypt(real_data,Decrypt_data,(uint8*)AES_KEY,real_len);
        // printf("\nDecrypt_len = %d\n",real_len);
        // printf("\nDecrypt_data = ");
        // for(uint8_t k =0;k<real_len;k++)
        // {
        //     printf("%x ",Decrypt_data[k]);
        // }
        if(Decrypt_data[3] == 0x01)
        {
            Read_Status_Send();
        }
        else if(Decrypt_data[3] == 0x50)
        {
            Decompress_wifi(Decrypt_data,real_len);
            Notify_Mode_Param_Send();
        }
        else if(Decrypt_data[3] == 0x00)
        {
            cmd_pack_and_send(CMD_SESSION_START,0x0009,NULL,0);
        }
        else
        {
            printf("\nUnknown Cmd\n");
        }
        real_len = 0;
        memset(real_data,0,64);
        memset(receive_data,0,64);
    }
    receive_len = 0;
#endif
}

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
#ifdef CONFIG_SET_RAW_ADV_DATA
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~adv_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~scan_rsp_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
#else
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
        adv_config_done &= (~adv_config_flag);
        if (adv_config_done == 0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
        adv_config_done &= (~scan_rsp_config_flag);
        if (adv_config_done == 0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
#endif
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        //advertising start complete event to indicate advertising start successfully or failed
        if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising start failed\n");
        }
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        if (param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising stop failed\n");
        } else {
            ESP_LOGI(GATTS_TAG, "Stop adv successfully\n");
        }
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
         ESP_LOGI(GATTS_TAG, "update connection params status = %d, min_int = %d, max_int = %d,conn_int = %d,latency = %d, timeout = %d",
                  param->update_conn_params.status,
                  param->update_conn_params.min_int,
                  param->update_conn_params.max_int,
                  param->update_conn_params.conn_int,
                  param->update_conn_params.latency,
                  param->update_conn_params.timeout);
        break;
    default:
        break;
    }
}

void example_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param){
    esp_gatt_status_t status = ESP_GATT_OK;
    if (param->write.need_rsp){
        if (param->write.is_prep){
            if (prepare_write_env->prepare_buf == NULL) {
                prepare_write_env->prepare_buf = (uint8_t *)malloc(PREPARE_BUF_MAX_SIZE*sizeof(uint8_t));
                prepare_write_env->prepare_len = 0;
                if (prepare_write_env->prepare_buf == NULL) {
                    ESP_LOGE(GATTS_TAG, "Gatt_server prep no mem\n");
                    status = ESP_GATT_NO_RESOURCES;
                }
            } else {
                if(param->write.offset > PREPARE_BUF_MAX_SIZE) {
                    status = ESP_GATT_INVALID_OFFSET;
                } else if ((param->write.offset + param->write.len) > PREPARE_BUF_MAX_SIZE) {
                    status = ESP_GATT_INVALID_ATTR_LEN;
                }
            }

            esp_gatt_rsp_t *gatt_rsp = (esp_gatt_rsp_t *)malloc(sizeof(esp_gatt_rsp_t));
            gatt_rsp->attr_value.len = param->write.len;
            gatt_rsp->attr_value.handle = param->write.handle;
            gatt_rsp->attr_value.offset = param->write.offset;
            gatt_rsp->attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
            memcpy(gatt_rsp->attr_value.value, param->write.value, param->write.len);
            esp_err_t response_err = esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, status, gatt_rsp);
            if (response_err != ESP_OK){
               ESP_LOGE(GATTS_TAG, "Send response error\n");
            }
            free(gatt_rsp);
            if (status != ESP_GATT_OK){
                return;
            }
            memcpy(prepare_write_env->prepare_buf + param->write.offset,
                   param->write.value,
                   param->write.len);
            prepare_write_env->prepare_len += param->write.len;

        }else{
            esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, status, NULL);
        }
    }
}

void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param){
    if (param->exec_write.exec_write_flag == ESP_GATT_PREP_WRITE_EXEC){
        esp_log_buffer_hex(GATTS_TAG, prepare_write_env->prepare_buf, prepare_write_env->prepare_len);
    }else{
        ESP_LOGI(GATTS_TAG,"ESP_GATT_PREP_WRITE_CANCEL");
    }
    if (prepare_write_env->prepare_buf) {
        free(prepare_write_env->prepare_buf);
        prepare_write_env->prepare_buf = NULL;
    }
    prepare_write_env->prepare_len = 0;
}

static void gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status %d, app_id %d\n", param->reg.status, param->reg.app_id);
        gl_profile_tab[PROFILE_A_APP_ID].service_id.is_primary = true;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.inst_id = 0x00;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.len = ESP_UUID_LEN_128;
        memcpy(gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.uuid.uuid128,GATTS_SERVICE_UUID_TEST_A,sizeof(GATTS_SERVICE_UUID_TEST_A)/sizeof(GATTS_SERVICE_UUID_TEST_A[0]));
        // gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.uuid.uuid128 = GATTS_SERVICE_UUID_TEST_A;

        esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(TEST_DEVICE_NAME);
        if (set_dev_name_ret){
            ESP_LOGE(GATTS_TAG, "set device name failed, error code = %x", set_dev_name_ret);
        }
#ifdef CONFIG_SET_RAW_ADV_DATA
        esp_err_t raw_adv_ret = esp_ble_gap_config_adv_data_raw(raw_adv_data, sizeof(raw_adv_data));
        if (raw_adv_ret){
            ESP_LOGE(GATTS_TAG, "config raw adv data failed, error code = %x ", raw_adv_ret);
        }
        adv_config_done |= adv_config_flag;
        esp_err_t raw_scan_ret = esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp_data, sizeof(raw_scan_rsp_data));
        if (raw_scan_ret){
            ESP_LOGE(GATTS_TAG, "config raw scan rsp data failed, error code = %x", raw_scan_ret);
        }
        adv_config_done |= scan_rsp_config_flag;
#else
        //config adv data
        esp_err_t ret = esp_ble_gap_config_adv_data(&adv_data);
        if (ret){
            ESP_LOGE(GATTS_TAG, "config adv data failed, error code = %x", ret);
        }
        adv_config_done |= adv_config_flag;
        //config scan response data
        ret = esp_ble_gap_config_adv_data(&scan_rsp_data);
        if (ret){
            ESP_LOGE(GATTS_TAG, "config scan response data failed, error code = %x", ret);
        }
        adv_config_done |= scan_rsp_config_flag;

#endif
        esp_ble_gatts_create_service(gatts_if, &gl_profile_tab[PROFILE_A_APP_ID].service_id, GATTS_NUM_HANDLE_TEST_A);
        break;
    case ESP_GATTS_READ_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %d, trans_id %" PRIu32 ", handle %d\n", param->read.conn_id, param->read.trans_id, param->read.handle);
        esp_gatt_rsp_t rsp;
        // uint32_t len;
        send_num++;
        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->read.handle;
        printf("\nrsp.attr_value.handle = %d\n",rsp.attr_value.handle);
        rsp.attr_value.len = 4;
        rsp.attr_value.value[0] = 0xde;
        rsp.attr_value.value[1] = 0xed;
        rsp.attr_value.value[2] = 0xae;
        rsp.attr_value.value[3] = 0xef;
        // aesECB128Encrypt(rsp.attr_value.value,Gatt_AES_value,(uint8*)AES_KEY,rsp.attr_value.len);
        // memcpy(rsp.attr_value.value,Gatt_AES_value,sizeof(Gatt_AES_value)/sizeof(Gatt_AES_value[0]));
        // memset(Gatt_AES_value,0,sizeof(Gatt_AES_value)/sizeof(Gatt_AES_value[0]));
        // len=aesECB128Decrypt(rsp.attr_value.value,Gatt_AES_value,(uint8*)AES_KEY,16);
        // memcpy(rsp.attr_value.value,Gatt_AES_value,sizeof(Gatt_AES_value)/sizeof(Gatt_AES_value[0]));
        printf("\ngatts_if = %d, param->read.conn_id = %d, param->read.trans_id = %ld\n",gatts_if,param->read.conn_id,param->read.trans_id);
        // esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id,
                                    // ESP_GATT_OK, &rsp);
        esp_ble_gatts_send_response(3, 0, send_num,ESP_GATT_OK, &rsp);
        break;
    }
    case ESP_GATTS_WRITE_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %d, trans_id %" PRIu32 ", handle %d", param->write.conn_id, param->write.trans_id, param->write.handle);
        if (!param->write.is_prep){
            ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, value len %d, value :", param->write.len);
            esp_log_buffer_hex(GATTS_TAG, param->write.value, param->write.len);
            receive_len = param->write.len;
            memcpy(receive_data,param->write.value,receive_len);
            if (gl_profile_tab[PROFILE_A_APP_ID].descr_handle == param->write.handle && param->write.len == 2){
                uint16_t descr_value = param->write.value[1]<<8 | param->write.value[0];
                if (descr_value == 0x0001){
                    if (a_property & ESP_GATT_CHAR_PROP_BIT_NOTIFY){
                        ESP_LOGI(GATTS_TAG, "notify enable");
                        uint8_t notify_data[15];
                        for (int i = 0; i < sizeof(notify_data); ++i)
                        {
                            notify_data[i] = i%0xff;
                        }
                        //the size of notify_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_A_APP_ID].char_handle,
                                                sizeof(notify_data), notify_data, false);
                    }
                }else if (descr_value == 0x0002){
                    if (a_property & ESP_GATT_CHAR_PROP_BIT_INDICATE){
                        ESP_LOGI(GATTS_TAG, "indicate enable");
                        uint8_t indicate_data[15];
                        for (int i = 0; i < sizeof(indicate_data); ++i)
                        {
                            indicate_data[i] = i%0xff;
                        }
                        //the size of indicate_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_A_APP_ID].char_handle,
                                                sizeof(indicate_data), indicate_data, true);
                    }
                }
                else if (descr_value == 0x0000){
                    ESP_LOGI(GATTS_TAG, "notify/indicate disable ");
                }else{
                    ESP_LOGE(GATTS_TAG, "unknown descr value");
                    esp_log_buffer_hex(GATTS_TAG, param->write.value, param->write.len);
                }

            }
        }
        example_write_event_env(gatts_if, &a_prepare_write_env, param);
        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
        example_exec_write_event_env(&a_prepare_write_env, param);
        break;
    case ESP_GATTS_MTU_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_MTU_EVT, MTU %d", param->mtu.mtu);
        break;
    case ESP_GATTS_UNREG_EVT:
        break;
    case ESP_GATTS_CREATE_EVT:
        ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, status %d,  service_handle %d\n", param->create.status, param->create.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].service_handle = param->create.service_handle;
        gl_profile_tab[PROFILE_A_APP_ID].char_uuid.len = ESP_UUID_LEN_128;
        memcpy(gl_profile_tab[PROFILE_A_APP_ID].char_uuid.uuid.uuid128,GATTS_CHAR_UUID_TEST_A,sizeof(GATTS_CHAR_UUID_TEST_A));
        // gl_profile_tab[PROFILE_A_APP_ID].char_uuid.uuid.uuid16 = GATTS_CHAR_UUID_TEST_A;

        esp_ble_gatts_start_service(gl_profile_tab[PROFILE_A_APP_ID].service_handle);
        a_property = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
        esp_err_t add_char_ret = esp_ble_gatts_add_char(gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].char_uuid,
                                                        ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                                        a_property,
                                                        &gatts_demo_char1_val, NULL);
        if (add_char_ret){
            ESP_LOGE(GATTS_TAG, "add char failed, error code =%x",add_char_ret);
        }
        break;
    case ESP_GATTS_ADD_INCL_SRVC_EVT:
        break;
    case ESP_GATTS_ADD_CHAR_EVT: {
        uint16_t length = 0;
        const uint8_t *prf_char;

        ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status %d,  attr_handle %d, service_handle %d\n",
                param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].char_handle = param->add_char.attr_handle;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
        esp_err_t get_attr_ret = esp_ble_gatts_get_attr_value(param->add_char.attr_handle,  &length, &prf_char);
        if (get_attr_ret == ESP_FAIL){
            ESP_LOGE(GATTS_TAG, "ILLEGAL HANDLE");
        }

        ESP_LOGI(GATTS_TAG, "the gatts demo char length = %x\n", length);
        for(int i = 0; i < length; i++){
            ESP_LOGI(GATTS_TAG, "prf_char[%x] =%x\n",i,prf_char[i]);
        }
        esp_err_t add_descr_ret = esp_ble_gatts_add_char_descr(gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].descr_uuid,
                                                                ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, NULL, NULL);
        if (add_descr_ret){
            ESP_LOGE(GATTS_TAG, "add char descr failed, error code =%x", add_descr_ret);
        }
        break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT:
        gl_profile_tab[PROFILE_A_APP_ID].descr_handle = param->add_char_descr.attr_handle;
        ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT, status %d, attr_handle %d, service_handle %d\n",
                 param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
        break;
    case ESP_GATTS_DELETE_EVT:
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(GATTS_TAG, "SERVICE_START_EVT, status %d, service_handle %d\n",
                 param->start.status, param->start.service_handle);
        break;
    case ESP_GATTS_STOP_EVT:
        break;
    case ESP_GATTS_CONNECT_EVT: {
        esp_ble_conn_update_params_t conn_params = {0};
        memcpy(conn_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
        /* For the IOS system, please reference the apple official documents about the ble connection parameters restrictions. */
        conn_params.latency = 0;
        conn_params.max_int = 0x20;    // max_int = 0x20*1.25ms = 40ms
        conn_params.min_int = 0x10;    // min_int = 0x10*1.25ms = 20ms
        conn_params.timeout = 400;    // timeout = 400*10ms = 4000ms
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONNECT_EVT, conn_id %d, remote %02x:%02x:%02x:%02x:%02x:%02x:",
                 param->connect.conn_id,
                 param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
                 param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
        gl_profile_tab[PROFILE_A_APP_ID].conn_id = param->connect.conn_id;
        //start sent the update connection parameters to the peer device.
        esp_ble_gap_update_conn_params(&conn_params);
        break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_DISCONNECT_EVT, disconnect reason 0x%x", param->disconnect.reason);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_CONF_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONF_EVT, status %d attr_handle %d", param->conf.status, param->conf.handle);
        if (param->conf.status != ESP_GATT_OK){
            esp_log_buffer_hex(GATTS_TAG, param->conf.value, param->conf.len);
        }
        break;
    case ESP_GATTS_OPEN_EVT:
    case ESP_GATTS_CANCEL_OPEN_EVT:
    case ESP_GATTS_CLOSE_EVT:
    case ESP_GATTS_LISTEN_EVT:
    case ESP_GATTS_CONGEST_EVT:
    default:
        break;
    }
}

static void gatts_profile_b_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status %d, app_id %d\n", param->reg.status, param->reg.app_id);
        gl_profile_tab[PROFILE_B_APP_ID].service_id.is_primary = true;
        gl_profile_tab[PROFILE_B_APP_ID].service_id.id.inst_id = 0x00;
        gl_profile_tab[PROFILE_B_APP_ID].service_id.id.uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_B_APP_ID].service_id.id.uuid.uuid.uuid16 = GATTS_SERVICE_UUID_TEST_B;

        esp_ble_gatts_create_service(gatts_if, &gl_profile_tab[PROFILE_B_APP_ID].service_id, GATTS_NUM_HANDLE_TEST_B);
        break;
    case ESP_GATTS_READ_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %d, trans_id %" PRIu32 ", handle %d\n", param->read.conn_id, param->read.trans_id, param->read.handle);
        esp_gatt_rsp_t rsp;
        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->read.handle;
        rsp.attr_value.len = 4;
        rsp.attr_value.value[0] = 0xde;
        rsp.attr_value.value[1] = 0xed;
        rsp.attr_value.value[2] = 0xbe;
        rsp.attr_value.value[3] = 0xef;
        esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id,
                                    ESP_GATT_OK, &rsp);
        break;
    }
    case ESP_GATTS_WRITE_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %d, trans_id %" PRIu32 ", handle %d\n", param->write.conn_id, param->write.trans_id, param->write.handle);
        if (!param->write.is_prep){
            ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, value len %d, value :", param->write.len);
            esp_log_buffer_hex(GATTS_TAG, param->write.value, param->write.len);
            if (gl_profile_tab[PROFILE_B_APP_ID].descr_handle == param->write.handle && param->write.len == 2){
                uint16_t descr_value= param->write.value[1]<<8 | param->write.value[0];
                if (descr_value == 0x0001){
                    if (b_property & ESP_GATT_CHAR_PROP_BIT_NOTIFY){
                        ESP_LOGI(GATTS_TAG, "notify enable");
                        uint8_t notify_data[15];
                        for (int i = 0; i < sizeof(notify_data); ++i)
                        {
                            notify_data[i] = i%0xff;
                        }
                        //the size of notify_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_B_APP_ID].char_handle,
                                                sizeof(notify_data), notify_data, false);
                    }
                }else if (descr_value == 0x0002){
                    if (b_property & ESP_GATT_CHAR_PROP_BIT_INDICATE){
                        ESP_LOGI(GATTS_TAG, "indicate enable");
                        uint8_t indicate_data[15];
                        for (int i = 0; i < sizeof(indicate_data); ++i)
                        {
                            indicate_data[i] = i%0xff;
                        }
                        //the size of indicate_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_B_APP_ID].char_handle,
                                                sizeof(indicate_data), indicate_data, true);
                    }
                }
                else if (descr_value == 0x0000){
                    ESP_LOGI(GATTS_TAG, "notify/indicate disable ");
                }else{
                    ESP_LOGE(GATTS_TAG, "unknown value");
                }

            }
        }
        example_write_event_env(gatts_if, &b_prepare_write_env, param);
        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
        example_exec_write_event_env(&b_prepare_write_env, param);
        break;
    case ESP_GATTS_MTU_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_MTU_EVT, MTU %d", param->mtu.mtu);
        break;
    case ESP_GATTS_UNREG_EVT:
        break;
    case ESP_GATTS_CREATE_EVT:
        ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, status %d,  service_handle %d\n", param->create.status, param->create.service_handle);
        gl_profile_tab[PROFILE_B_APP_ID].service_handle = param->create.service_handle;
        gl_profile_tab[PROFILE_B_APP_ID].char_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_B_APP_ID].char_uuid.uuid.uuid16 = GATTS_CHAR_UUID_TEST_B;

        esp_ble_gatts_start_service(gl_profile_tab[PROFILE_B_APP_ID].service_handle);
        b_property = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
        esp_err_t add_char_ret =esp_ble_gatts_add_char( gl_profile_tab[PROFILE_B_APP_ID].service_handle, &gl_profile_tab[PROFILE_B_APP_ID].char_uuid,
                                                        ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                                        b_property,
                                                        NULL, NULL);
        if (add_char_ret){
            ESP_LOGE(GATTS_TAG, "add char failed, error code =%x",add_char_ret);
        }
        break;
    case ESP_GATTS_ADD_INCL_SRVC_EVT:
        break;
    case ESP_GATTS_ADD_CHAR_EVT:
        ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status %d,  attr_handle %d, service_handle %d\n",
                 param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);

        gl_profile_tab[PROFILE_B_APP_ID].char_handle = param->add_char.attr_handle;
        gl_profile_tab[PROFILE_B_APP_ID].descr_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_B_APP_ID].descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
        esp_ble_gatts_add_char_descr(gl_profile_tab[PROFILE_B_APP_ID].service_handle, &gl_profile_tab[PROFILE_B_APP_ID].descr_uuid,
                                     ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                     NULL, NULL);
        break;
    case ESP_GATTS_ADD_CHAR_DESCR_EVT:
        gl_profile_tab[PROFILE_B_APP_ID].descr_handle = param->add_char_descr.attr_handle;
        ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT, status %d, attr_handle %d, service_handle %d\n",
                 param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
        break;
    case ESP_GATTS_DELETE_EVT:
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(GATTS_TAG, "SERVICE_START_EVT, status %d, service_handle %d\n",
                 param->start.status, param->start.service_handle);
        break;
    case ESP_GATTS_STOP_EVT:
        break;
    case ESP_GATTS_CONNECT_EVT:
        ESP_LOGI(GATTS_TAG, "CONNECT_EVT, conn_id %d, remote %02x:%02x:%02x:%02x:%02x:%02x:",
                 param->connect.conn_id,
                 param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
                 param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
        gl_profile_tab[PROFILE_B_APP_ID].conn_id = param->connect.conn_id;
        break;
    case ESP_GATTS_CONF_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONF_EVT status %d attr_handle %d", param->conf.status, param->conf.handle);
        if (param->conf.status != ESP_GATT_OK){
            esp_log_buffer_hex(GATTS_TAG, param->conf.value, param->conf.len);
        }
    break;
    case ESP_GATTS_DISCONNECT_EVT:
    case ESP_GATTS_OPEN_EVT:
    case ESP_GATTS_CANCEL_OPEN_EVT:
    case ESP_GATTS_CLOSE_EVT:
    case ESP_GATTS_LISTEN_EVT:
    case ESP_GATTS_CONGEST_EVT:
    default:
        break;
    }
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    /* If event is register event, store the gatts_if for each profile */
    if (event == ESP_GATTS_REG_EVT) {
        if (param->reg.status == ESP_GATT_OK) {
            gl_profile_tab[param->reg.app_id].gatts_if = gatts_if;
        } else {
            ESP_LOGI(GATTS_TAG, "Reg app failed, app_id %04x, status %d\n",
                    param->reg.app_id,
                    param->reg.status);
            return;
        }
    }

    /* If the gatts_if equal to profile A, call profile A cb handler,
     * so here call each profile's callback */
    do {
        int idx;
        for (idx = 0; idx < PROFILE_NUM; idx++) {
            if (gatts_if == ESP_GATT_IF_NONE || /* ESP_GATT_IF_NONE, not specify a certain gatt_if, need to call every profile cb function */
                    gatts_if == gl_profile_tab[idx].gatts_if) {
                if (gl_profile_tab[idx].gatts_cb) {
                    gl_profile_tab[idx].gatts_cb(event, gatts_if, param);
                }
            }
        }
    } while (0);
}

int md5_calculate(char argv[],uint8_t len)
{
	int i;
    register unsigned char *x,*z;
    register char *y;
    unsigned char decrypt[16];
    unsigned char str[16];

    memset(keyCode_charge,'\0',keyCode_len);
    memset(secretKey,'\0',50);
    for( x = keyCode_charge, y = argv ; y < (&argv[0] + len) ; )
		*x++ = *y++;
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,keyCode_charge,strlen((char *)keyCode_charge));
	MD5Final(&md5,decrypt);        
	// printf("加密前:%s\n加密后:",keyCode_test);
	// for(i=0;i<16;i++)
	// {
	// 	printf("%02x",decrypt[i]);
	// }
    for( x = str, z = decrypt ; z < &decrypt[16] ; )
		*x++ = *z++;
    for(i=0;i<16;i++)
    {
        sprintf(secretKey + i * 2, "%02x", str[i]);
    }
	return 0;
}

static void cJSON_decompression(void)
{
    cJSON *pJsonRoot = cJSON_Parse(response_buffer);
    if (pJsonRoot !=NULL)
    {
        cJSON *pdataJson = cJSON_GetObjectItem(pJsonRoot, "dataJson");
        if (!pdataJson) return;                                     
        else
        {
            cJSON *psecretKey = cJSON_GetObjectItem(pdataJson, "secretKey");
            if(psecretKey)
            {
                if (cJSON_IsString(psecretKey))                           
                {
                    memset(return_secretKey,'\0',50);
                    strcpy(return_secretKey, psecretKey->valuestring);               // 拷贝内容到字符串数组
                }
            }
            cJSON *ptimestamp = cJSON_GetObjectItem(pdataJson, "timestamp");
            if(ptimestamp)
            {
                timestamp = (uint64_t)ptimestamp->valuedouble;
            }
        }
    }
    cJSON_Delete(pJsonRoot);
}

static void device_activate(void)
{
    pRoot = cJSON_CreateObject();                         // 创建JSON根部结构体
    // pValue = cJSON_CreateObject();                        // 创建JSON子叶结构体 

    sprintf(timestamp_string,"%lld",timestamp);
    memset(keyCode,'\0',keyCode_len);
    strcat(keyCode,deviceCode);
    strcat(keyCode,timestamp_string);
    strcat(keyCode,deviceCode);
    md5_calculate(keyCode,keyCode_len);

    cJSON_AddStringToObject(pRoot,"deviceCode",deviceCode);
    cJSON_AddNumberToObject(pRoot,"timestamp",timestamp);
    cJSON_AddStringToObject(pRoot,"keyCode",secretKey);
    sendData = cJSON_PrintUnformatted(pRoot);
}

static void http_native_request(void)
{
    char output_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};   // Buffer to store response of http request
    int content_length = 0;

    esp_http_client_config_t config = {
        .url = "http://zjk.icheer.cn/eiker_application_gateway/iot/device/config/activate",
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET Request
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRIu64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, data_read);
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    esp_http_client_close(client);

    // POST Request
    //const char *post_data = "{\"field1\":\"value1\"}";
    // char *post_data = "{\"deviceCode\":\"10000025\",\"timestamp\":\"88888888\",\"keyCode\":\"84417296ecc3a8a399da08aa79c26c35\"}";
    // const char post_data[] = "{\"deviceCode\":\"10000025\",\"timestamp\":\"88888888\",\"keyCode\":\"84417296ecc3a8a399da08aa79c26c35\"}";
    device_activate();
    char *post_data = sendData;
    esp_http_client_set_url(client, "http://zjk.icheer.cn/eiker_application_gateway/iot/device/config/activate");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    err = esp_http_client_open(client, strlen(post_data));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        int wlen = esp_http_client_write(client, post_data, strlen(post_data));
        if (wlen < 0) {
            ESP_LOGE(TAG, "Write failed");
        }
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRIu64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                esp_http_client_printf_data(client);
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, strlen(output_buffer));
                memset(response_buffer,'\0',MAX_HTTP_OUTPUT_BUFFER);
                memcpy(response_buffer,output_buffer,MAX_HTTP_OUTPUT_BUFFER);
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    cJSON_free(sendData);
    cJSON_Delete(pRoot);
    esp_http_client_cleanup(client);
    Device_Status = 1;
    Notify_Mode_Param_Send();
    xTimerStart(device_heartbeat,0);
    xTimerStart(device_data,0);
}

static void http_test_task(void *pvParameters)
{
    http_native_request();
    ESP_LOGI(TAG, "Finish http example");
#if !CONFIG_IDF_TARGET_LINUX
    vTaskDelete(NULL);
#endif
}

static void heartbeat_process(void)
{
    pRoot = cJSON_CreateObject();                         // 创建JSON根部结构体

    cJSON_decompression();
    memset(keyCode,'\0',keyCode_len);
    memset(timestamp_string,'\0',50);
    timestamp +=60000;

    sprintf(timestamp_string,"%lld",timestamp);
    strcat(keyCode,deviceCode);
    strcat(keyCode,timestamp_string);
    strcat(keyCode,return_secretKey);
    md5_calculate(keyCode,keyCode_len);

    cJSON_AddStringToObject(pRoot,"deviceCode",deviceCode);
    cJSON_AddNumberToObject(pRoot,"timestamp",timestamp);
    cJSON_AddStringToObject(pRoot,"keyCode",secretKey);
    sendData = cJSON_PrintUnformatted(pRoot);
}

static void device_heartbeat_process(void)
{
    char output_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};   // Buffer to store response of http request
    int content_length = 0;
    esp_http_client_config_t config = {
        .url = "http://zjk.icheer.cn/eiker_application_gateway/iot/device/config/heartbeat",
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err;

    heartbeat_process();
    char *post_data = sendData;
    esp_http_client_set_url(client, "http://zjk.icheer.cn/eiker_application_gateway/iot/device/config/heartbeat");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    err = esp_http_client_open(client, strlen(post_data));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        int wlen = esp_http_client_write(client, post_data, strlen(post_data));
        if (wlen < 0) {
            ESP_LOGE(TAG, "Write failed");
        }
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRIu64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                esp_http_client_printf_data(client);
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, strlen(output_buffer));
                memset(response_buffer,'\0',MAX_HTTP_OUTPUT_BUFFER);
                memcpy(response_buffer,output_buffer,MAX_HTTP_OUTPUT_BUFFER);
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    cJSON_free(sendData);
    cJSON_Delete(pRoot);
    esp_http_client_cleanup(client);
}

static void iot_data_process(void)
{
    pRoot = cJSON_CreateObject();                         // 创建JSON根部结构体

    cJSON_decompression();
    memset(keyCode,'\0',keyCode_len);
    memset(timestamp_string,'\0',50);
    memset(battery_string,'\0',6);
    memset(paper_string,'\0',6);
    memset(liquid_string,'\0',6);
    battery = rand()%100;
    liquid = rand()%100;
    paper = rand()%100;
    sprintf(timestamp_string,"%lld",timestamp);
    sprintf(battery_string,"%d",battery);
    sprintf(paper_string,"%d",paper);
    sprintf(liquid_string,"%d",liquid);
    strcat(keyCode,battery_string);
    strcat(keyCode,deviceCode);
    strcat(keyCode,liquid_string);
    strcat(keyCode,paper_string);
    strcat(keyCode,timestamp_string);
    strcat(keyCode,return_secretKey);
    md5_calculate(keyCode,keyCode_len);


    cJSON_AddStringToObject(pRoot,"deviceCode",deviceCode);
    cJSON_AddNumberToObject(pRoot,"timestamp",timestamp);
    cJSON_AddStringToObject(pRoot,"keyCode",secretKey);
    cJSON_AddNumberToObject(pRoot,"battery",battery);
    cJSON_AddNumberToObject(pRoot,"paper",paper);
    cJSON_AddNumberToObject(pRoot,"liquid",liquid);
    sendData = cJSON_PrintUnformatted(pRoot);
}

static void device_data_process(void)
{
    char output_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};   // Buffer to store response of http request
    int content_length = 0;
    esp_http_client_config_t config = {
        .url = "http://zjk.icheer.cn/eiker_application_gateway/iot/device/running/collect",
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err;

    iot_data_process();
    char *post_data = sendData;
    esp_http_client_set_url(client, "http://zjk.icheer.cn/eiker_application_gateway/iot/device/running/collect");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    err = esp_http_client_open(client, strlen(post_data));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        int wlen = esp_http_client_write(client, post_data, strlen(post_data));
        if (wlen < 0) {
            ESP_LOGE(TAG, "Write failed");
        }
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRIu64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                esp_http_client_printf_data(client);
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, strlen(output_buffer));
                memset(response_buffer,'\0',MAX_HTTP_OUTPUT_BUFFER);
                memcpy(response_buffer,output_buffer,MAX_HTTP_OUTPUT_BUFFER);
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    cJSON_free(sendData);
    cJSON_Delete(pRoot);
    esp_http_client_cleanup(client);
}

static void wifi_reconnect_process(void)
{
    esp_err_t ret = example_wifi_connect_second();
    if(!ret)
    {
        ESP_LOGI(TAG, "Connected to AP, begin http example");
        xTaskCreate(&http_test_task, "http_test_task", 8192, NULL, 5, NULL);
    }
    vTaskDelete(NULL);
}

static void wifi_periodic_detection_process(void)
{
    if(wifi_disconnect_flag)
    {   
        xTaskCreate(&wifi_reconnect_process, "wifi_reconnect_process", 8192, NULL, 5, NULL);
    }
}

void app_main(void)
{
    esp_err_t ret;

    // Initialize NVS.
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gap register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gatts_app_register(PROFILE_A_APP_ID);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gatts_app_register(PROFILE_B_APP_ID);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }
    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(500);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }

    receive_data_process = xTimerCreate("receive_data_process",50/portTICK_PERIOD_MS,pdTRUE,0,receive_process);
    xTimerStart(receive_data_process,0);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    // get_wifi_ssid_password(wifi_ssid,wifi_password);
    ret = example_connect();
    if(!ret)
    {
        ESP_LOGI(TAG, "Connected to AP, begin http example");
        xTaskCreate(&http_test_task, "http_test_task", 8192, NULL, 5, NULL);
    }
    // ESP_ERROR_CHECK(example_connect());
    // wifi_reconnect = xTimerCreate("wifi_reconnect",10000/portTICK_PERIOD_MS,pdTRUE,0,wifi_reconnect_process);
    wifi_periodic_detection = xTimerCreate("wifi_periodic_detection",10000/portTICK_PERIOD_MS,pdTRUE,0,wifi_periodic_detection_process);
    device_heartbeat = xTimerCreate("device_heartbeat",60000/portTICK_PERIOD_MS,pdTRUE,0,device_heartbeat_process);
    device_data = xTimerCreate("device_data",180000/portTICK_PERIOD_MS,pdTRUE,0,device_data_process);
    xTimerStart(wifi_periodic_detection,0);

    return;
}
