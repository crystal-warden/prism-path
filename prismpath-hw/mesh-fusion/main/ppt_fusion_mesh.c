/* ppt_fusion_mesh.c — distributed Level M decision fusion across an ESP-NOW mesh of three ESP32 nodes.
 *
 * Each node senses ONE channel, projects it to a small band, and broadcasts that band over ESP-NOW.
 * Every node also hears the other two, so each holds all three bands and runs the SAME baked Level M
 * fusion table over them (fusion_mesh_table.h). The winning edge is the fused posture, computed
 * identically on every node by the byte-exact evaluator every substrate certifies.
 *
 *   slot 0  tof_a = VL53L0X rangefinder (GPIO21/22 I2C)   band 0=contact 1=near 2=mid 3=far
 *   slot 1  tof_b = second VL53L0X                        (same bands)
 *   slot 2  arm   = potentiometer (GPIO35 / ADC1_CH7)     band 0=low .. 3=high (arming knob)
 *
 * CRITICAL needs BOTH rangefinders close AND the knob armed — a region no single node reaches alone.
 * Projection (raw -> band) is plain code; the fused DECISION is the decidable table. One binary: each
 * board matches its own MAC against ROLES[] and self-selects its slot + sensor. The onboard LED (GPIO2)
 * shows the fused posture, so all three light the same: solid=CRITICAL, blink=WARN, off=OK.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_random.h"
#include "fusion_mesh_table.h"

#define UART        UART_NUM_0
#define TBL_MAX     640
#define REGS_MAX    (4 + 8 * 24)
#define STACK_MAX   64
#define LED_GPIO    2
#define BCAST_MS    200        /* sense + broadcast + re-fuse cadence */
#define STALE_MS    1500       /* a slot unheard longer than this reads the STALE sentinel band */
#define STALE_BAND  8          /* decidable sentinel fed to the fusion table for an unheard slot */

#define SDA_GPIO    21
#define SCL_GPIO    22
#define I2C_PORT    I2C_NUM_0
#define I2C_HZ      100000
#define TOF_ADDR    0x29
#define TO_TICKS    pdMS_TO_TICKS(100)

#define POT_ADC_UNIT  ADC_UNIT_1
#define POT_ADC_CHAN  ADC_CHANNEL_7    /* GPIO35 = ADC1_CH7 (survives Wi-Fi/ESP-NOW) */

#define EXPECT_ACKS 2          /* 3-node fleet: coordinator waits for the other two */
#define ACK_WIN_MS  500
#define FLIP_DELAY  120        /* ms from COMMIT receipt to the atomic fusion-rule flip */

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { M_VERDICT = 1, M_PREPARE = 2, M_ACK = 3, M_COMMIT = 4 };
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ---------------- UART status channel (own UART0, console disabled) ---------------- */
static void emit(const char *fmt, ...) {
    char b[160]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) uart_write_bytes(UART, b, n);
}

/* ---------------- evaluator core (interp.c, byte-exact) ---------------- */
static uint8_t tbl[TBL_MAX], regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_base;
static uint16_t rd16(const uint8_t *p){ return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static int32_t rd32(const uint8_t *p){ int32_t v; memcpy(&v,p,4); return v; }
static void wr32(uint8_t *p, int32_t v){ memcpy(p,&v,4); }
static uint8_t parse_table(uint16_t len){
    if(len<28) return 3;
    if(rd32(tbl)!=(int32_t)0x4D545050L||rd16(tbl+4)!=1) return 1;
    n_fields=rd16(tbl+6); n_atoms=rd16(tbl+10); n_nodes=rd16(tbl+12); n_edges=rd16(tbl+14); prog_len=rd16(tbl+16);
    atoms_off=28; nodes_off=atoms_off+8*n_atoms; edges_off=nodes_off+4*n_nodes; prog_base=edges_off+6*n_edges;
    return (prog_base+2*prog_len!=len)?3:0;
}
static uint8_t eval_atom(uint16_t ai){
    const uint8_t *a=tbl+atoms_off+8*(uint32_t)ai; uint16_t f=rd16(a); uint8_t op=a[2],aty=a[3]; int32_t av=rd32(a+4);
    const uint8_t *r=regs+4+8*(uint32_t)f; int32_t rty=rd32(r),rv=rd32(r+4);
    uint8_t ln=(rty==TY_BOOL||rty==TY_INT), rn=(aty==TY_BOOL||aty==TY_INT);
    switch(op){
    case 0: case 1:{ uint8_t eq; if(ln&&rn) eq=(rv==av); else if(rty==TY_STR&&aty==TY_STR) eq=(rv==av); else if(rty==TY_NONE&&aty==TY_NONE) eq=1; else eq=0; return op==0?eq:(uint8_t)!eq; }
    case 2: case 3: case 4: case 5: if(!(ln&&rn)) return 0; switch(op){case 2:return rv<av;case 3:return rv<=av;case 4:return rv>av;default:return rv>=av;}
    case 6: return rty==TY_NONE?0:(rv!=0);
    } return 0;
}
static int8_t eval_prog(uint16_t off,uint16_t cnt,uint8_t *err){
    uint8_t st[STACK_MAX]; int8_t sp=0;
    for(uint16_t i=0;i<cnt;i++){ uint16_t w=rd16(tbl+prog_base+2*(uint32_t)(off+i));
        if(w<0x8000){ if(sp>=STACK_MAX){*err=7;return 0;} st[sp++]=eval_atom(w); }
        else switch(w){ case 0x8000: st[sp-1]=(uint8_t)!st[sp-1]; break; case 0x8001: sp--; st[sp-1]=(uint8_t)(st[sp-1]&&st[sp]); break; case 0x8002: sp--; st[sp-1]=(uint8_t)(st[sp-1]||st[sp]); break; case 0x8003: if(sp>=STACK_MAX){*err=7;return 0;} st[sp++]=1; break; case 0x8004: if(sp>=STACK_MAX){*err=7;return 0;} st[sp++]=0; break; default: *err=8; return 0; } }
    return (int8_t)st[0];
}
static int8_t evaluate(uint16_t node,uint8_t *err){
    const uint8_t *n=tbl+nodes_off+4*(uint32_t)node; uint16_t eo=rd16(n),ec=rd16(n+2);
    for(uint16_t i=0;i<ec;i++){ const uint8_t *e=tbl+edges_off+6*(uint32_t)(eo+i); if(eval_prog(rd16(e+2),rd16(e+4),err)) return (int8_t)i; if(*err) return -1; }
    return -1;
}
static uint32_t fnv1a32(const uint8_t *b,uint16_t n){ uint32_t h=0x811C9DC5u; for(uint16_t i=0;i<n;i++){ h=(h^b[i])*0x01000193u; } return h; }

/* ---------------- fusion-rule swap state (two-phase commit, from ppt_mesh.c) ---------------- */
static uint32_t active_id;
static uint8_t staged[TBL_MAX]; static uint16_t staged_len; static uint32_t staged_id; static uint16_t staged_seq;
static volatile int64_t flip_at_us = 0; static uint32_t epoch = 0; static uint8_t node_id;
static int coord = 0; static uint16_t rollout_seq = 0; static int64_t ack_deadline_us = 0; static uint8_t acked[256]; static int ack_n = 0;
static void set_active(const uint8_t *t,uint16_t len,uint32_t id){ memcpy(tbl,t,len); parse_table(len); active_id=id; }
static const char* pname(uint32_t id){ return id==POLICY_ID_A?"A":(id==POLICY_ID_B?"B":"?"); }

/* ---------------- VL53L0X driver (Pololu-derived, ported from tof_probe.c) ---------------- */
#define SYSRANGE_START                              0x00
#define SYSTEM_SEQUENCE_CONFIG                       0x01
#define SYSTEM_INTERRUPT_CONFIG_GPIO                 0x0A
#define SYSTEM_INTERRUPT_CLEAR                       0x0B
#define RESULT_INTERRUPT_STATUS                      0x13
#define RESULT_RANGE_STATUS                          0x14
#define MSRC_CONFIG_CONTROL                          0x60
#define FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT  0x44
#define GPIO_HV_MUX_ACTIVE_HIGH                      0x84
#define DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD          0x4E
#define DYNAMIC_SPAD_REF_EN_START_OFFSET             0x4F
#define GLOBAL_CONFIG_SPAD_ENABLES_REF_0             0xB0
#define GLOBAL_CONFIG_REF_EN_START_SELECT            0xB6
#define VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV            0x89

typedef struct { uint8_t addr; int io_timeout_ms; uint8_t stop_variable; bool did_timeout; } vl53l0x_t;

static void v_wr8(vl53l0x_t *s, uint8_t reg, uint8_t val){ uint8_t b[2]={reg,val}; i2c_master_write_to_device(I2C_PORT,s->addr,b,2,TO_TICKS); }
static uint8_t v_rd8(vl53l0x_t *s, uint8_t reg){ uint8_t v=0; i2c_master_write_read_device(I2C_PORT,s->addr,&reg,1,&v,1,TO_TICKS); return v; }
static void v_wr16(vl53l0x_t *s, uint8_t reg, uint16_t val){ uint8_t b[3]={reg,(uint8_t)(val>>8),(uint8_t)(val&0xFF)}; i2c_master_write_to_device(I2C_PORT,s->addr,b,3,TO_TICKS); }
static uint16_t v_rd16(vl53l0x_t *s, uint8_t reg){ uint8_t v[2]={0,0}; i2c_master_write_read_device(I2C_PORT,s->addr,&reg,1,v,2,TO_TICKS); return ((uint16_t)v[0]<<8)|v[1]; }
static void v_wr_multi(vl53l0x_t *s, uint8_t reg, const uint8_t *src, uint8_t n){ uint8_t b[16]; b[0]=reg; memcpy(b+1,src,n); i2c_master_write_to_device(I2C_PORT,s->addr,b,n+1,TO_TICKS); }
static void v_rd_multi(vl53l0x_t *s, uint8_t reg, uint8_t *dst, uint8_t n){ i2c_master_write_read_device(I2C_PORT,s->addr,&reg,1,dst,n,TO_TICKS); }

static int64_t s_deadline_us;
static void start_timeout(vl53l0x_t *s){ s_deadline_us=esp_timer_get_time()+(int64_t)s->io_timeout_ms*1000; }
static bool timed_out(void){ return esp_timer_get_time()>s_deadline_us; }

static bool get_spad_info(vl53l0x_t *s, uint8_t *count, bool *type_is_aperture){
    v_wr8(s,0x80,0x01); v_wr8(s,0xFF,0x01); v_wr8(s,0x00,0x00);
    v_wr8(s,0xFF,0x06); v_wr8(s,0x83,v_rd8(s,0x83)|0x04);
    v_wr8(s,0xFF,0x07); v_wr8(s,0x81,0x01); v_wr8(s,0x80,0x01);
    v_wr8(s,0x94,0x6b); v_wr8(s,0x83,0x00);
    start_timeout(s);
    while(v_rd8(s,0x83)==0x00){ if(timed_out()) return false; }
    v_wr8(s,0x83,0x01);
    uint8_t tmp=v_rd8(s,0x92); *count=tmp&0x7f; *type_is_aperture=(tmp>>7)&0x01;
    v_wr8(s,0x81,0x00); v_wr8(s,0xFF,0x06); v_wr8(s,0x83,v_rd8(s,0x83)&~0x04);
    v_wr8(s,0xFF,0x01); v_wr8(s,0x00,0x01); v_wr8(s,0xFF,0x00); v_wr8(s,0x80,0x00);
    return true;
}
static bool ref_calibration(vl53l0x_t *s, uint8_t vhv_init_byte){
    v_wr8(s,SYSRANGE_START,0x01|vhv_init_byte);
    start_timeout(s);
    while((v_rd8(s,RESULT_INTERRUPT_STATUS)&0x07)==0){ if(timed_out()) return false; }
    v_wr8(s,SYSTEM_INTERRUPT_CLEAR,0x01); v_wr8(s,SYSRANGE_START,0x00);
    return true;
}
static bool vl53l0x_init(vl53l0x_t *s, uint8_t addr){
    s->addr=addr; s->io_timeout_ms=500; s->did_timeout=false;
    if(v_rd8(s,0xC0)!=0xEE) return false;
    v_wr8(s,VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV,v_rd8(s,VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV)|0x01);
    v_wr8(s,0x88,0x00); v_wr8(s,0x80,0x01); v_wr8(s,0xFF,0x01); v_wr8(s,0x00,0x00);
    s->stop_variable=v_rd8(s,0x91);
    v_wr8(s,0x00,0x01); v_wr8(s,0xFF,0x00); v_wr8(s,0x80,0x00);
    v_wr8(s,MSRC_CONFIG_CONTROL,v_rd8(s,MSRC_CONFIG_CONTROL)|0x12);
    v_wr16(s,FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT,(uint16_t)(0.25*(1<<7)));
    v_wr8(s,SYSTEM_SEQUENCE_CONFIG,0xFF);
    uint8_t spad_count; bool spad_type_is_aperture;
    if(!get_spad_info(s,&spad_count,&spad_type_is_aperture)) return false;
    uint8_t ref_spad_map[6]; v_rd_multi(s,GLOBAL_CONFIG_SPAD_ENABLES_REF_0,ref_spad_map,6);
    v_wr8(s,0xFF,0x01); v_wr8(s,DYNAMIC_SPAD_REF_EN_START_OFFSET,0x00);
    v_wr8(s,DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD,0x2C);
    v_wr8(s,0xFF,0x00); v_wr8(s,GLOBAL_CONFIG_REF_EN_START_SELECT,0xB4);
    uint8_t first_spad=spad_type_is_aperture?12:0, enabled=0;
    for(uint8_t i=0;i<48;i++){
        if(i<first_spad||enabled==spad_count) ref_spad_map[i/8]&=~(1<<(i%8));
        else if((ref_spad_map[i/8]>>(i%8))&0x1) enabled++;
    }
    v_wr_multi(s,GLOBAL_CONFIG_SPAD_ENABLES_REF_0,ref_spad_map,6);
    static const uint8_t tuning[]={
        0xFF,0x01, 0x00,0x00, 0xFF,0x00, 0x09,0x00, 0x10,0x00, 0x11,0x00, 0x24,0x01, 0x25,0xFF,
        0x75,0x00, 0xFF,0x01, 0x4E,0x2C, 0x48,0x00, 0x30,0x20, 0xFF,0x00, 0x30,0x09, 0x54,0x00,
        0x31,0x04, 0x32,0x03, 0x40,0x83, 0x46,0x25, 0x60,0x00, 0x27,0x00, 0x50,0x06, 0x51,0x00,
        0x52,0x96, 0x56,0x08, 0x57,0x30, 0x61,0x00, 0x62,0x00, 0x64,0x00, 0x65,0x00, 0x66,0xA0,
        0xFF,0x01, 0x22,0x32, 0x47,0x14, 0x49,0xFF, 0x4A,0x00, 0xFF,0x00, 0x7A,0x0A, 0x7B,0x00,
        0x78,0x21, 0xFF,0x01, 0x23,0x34, 0x42,0x00, 0x44,0xFF, 0x45,0x26, 0x46,0x05, 0x40,0x40,
        0x0E,0x06, 0x20,0x1A, 0x43,0x40, 0xFF,0x00, 0x34,0x03, 0x35,0x44, 0xFF,0x01, 0x31,0x04,
        0x4B,0x09, 0x4C,0x05, 0x4D,0x04, 0xFF,0x00, 0x44,0x00, 0x45,0x20, 0x47,0x08, 0x48,0x28,
        0x67,0x00, 0x70,0x04, 0x71,0x01, 0x72,0xFE, 0x76,0x00, 0x77,0x00, 0xFF,0x01, 0x0D,0x01,
        0xFF,0x00, 0x80,0x01, 0x01,0xF8, 0xFF,0x01, 0x8E,0x01, 0x00,0x01, 0xFF,0x00, 0x80,0x00,
    };
    for(size_t i=0;i<sizeof(tuning);i+=2) v_wr8(s,tuning[i],tuning[i+1]);
    v_wr8(s,SYSTEM_INTERRUPT_CONFIG_GPIO,0x04);
    v_wr8(s,GPIO_HV_MUX_ACTIVE_HIGH,v_rd8(s,GPIO_HV_MUX_ACTIVE_HIGH)&~0x10);
    v_wr8(s,SYSTEM_INTERRUPT_CLEAR,0x01);
    v_wr8(s,SYSTEM_SEQUENCE_CONFIG,0x01); if(!ref_calibration(s,0x40)) return false;
    v_wr8(s,SYSTEM_SEQUENCE_CONFIG,0x02); if(!ref_calibration(s,0x00)) return false;
    v_wr8(s,SYSTEM_SEQUENCE_CONFIG,0xE8);
    return true;
}
static uint16_t read_range_single(vl53l0x_t *s){
    v_wr8(s,0x80,0x01); v_wr8(s,0xFF,0x01); v_wr8(s,0x00,0x00);
    v_wr8(s,0x91,s->stop_variable);
    v_wr8(s,0x00,0x01); v_wr8(s,0xFF,0x00); v_wr8(s,0x80,0x00);
    v_wr8(s,SYSRANGE_START,0x01);
    start_timeout(s);
    while(v_rd8(s,SYSRANGE_START)&0x01){ if(timed_out()){ s->did_timeout=true; return 65535; } }
    start_timeout(s);
    while((v_rd8(s,RESULT_INTERRUPT_STATUS)&0x07)==0){ if(timed_out()){ s->did_timeout=true; return 65535; } }
    uint16_t range=v_rd16(s,RESULT_RANGE_STATUS+10);
    v_wr8(s,SYSTEM_INTERRUPT_CLEAR,0x01);
    return range;
}

/* ---------------- projection: raw sensor -> band (plain code; the DECISION is the table) ---------- */
static int8_t project_tof(uint16_t mm){ if(mm<100) return 0; if(mm<300) return 1; if(mm<800) return 2; return 3; }
static int8_t project_pot(int raw){ if(raw<1024) return 0; if(raw<2048) return 1; if(raw<3072) return 2; return 3; }

/* ---------------- node role + fused state ---------------- */
static uint8_t my_slot = 0xFF, my_kind = 0xFF; static const char *my_label = "?";
static int8_t  bands[N_SLOTS];              /* latest band per slot, -1 = never heard */
static int64_t band_seen_us[N_SLOTS];
static vl53l0x_t tof; static bool tof_ok = false;
static adc_oneshot_unit_handle_t adc1;
static uint8_t drop_pct = 0;                /* simulated interference: % of received verdicts to drop */

/* ---------------- ESP-NOW ---------------- */
static QueueHandle_t rxq;
typedef struct { int len; uint8_t d[TBL_MAX+16]; } rxmsg_t;
static void on_recv(const esp_now_recv_info_t *info,const uint8_t *data,int len){ (void)info; if(len<=0||len>(int)sizeof(((rxmsg_t*)0)->d)) return; rxmsg_t m; m.len=len; memcpy(m.d,data,len); xQueueSend(rxq,&m,0); }
static void bcast(const uint8_t *d,int n){ esp_now_send(BCAST,d,n); }
static void send_verdict(uint8_t slot,int8_t band,uint16_t seq){ uint8_t b[5]={M_VERDICT,slot,(uint8_t)band,seq&0xFF,seq>>8}; bcast(b,5); }
static void send_prepare(uint32_t id,const uint8_t *t,uint16_t len,uint16_t seq){ uint8_t b[TBL_MAX+16]; int p=0; b[p++]=M_PREPARE; b[p++]=seq&0xFF; b[p++]=seq>>8; memcpy(b+p,&id,4); p+=4; b[p++]=len&0xFF; b[p++]=len>>8; memcpy(b+p,t,len); p+=len; bcast(b,p); }
static void send_ack(uint16_t seq){ uint8_t b[4]={M_ACK,seq&0xFF,seq>>8,node_id}; bcast(b,4); }
static void send_commit(uint16_t seq,uint16_t delay){ uint8_t b[5]={M_COMMIT,seq&0xFF,seq>>8,delay&0xFF,delay>>8}; bcast(b,5); }

/* poke over USB: coordinate a fleet-wide swap of the fusion RULE itself (toggle A<->B) */
static void start_rollout(void){
    uint32_t target_id=(active_id==POLICY_ID_A)?POLICY_ID_B:POLICY_ID_A;
    const uint8_t *t=(target_id==POLICY_ID_A)?FUSE_TABLE_A:FUSE_TABLE_B;
    uint16_t len=(target_id==POLICY_ID_A)?FUSE_TABLE_A_LEN:FUSE_TABLE_B_LEN;
    rollout_seq++;
    memcpy(staged,t,len); staged_len=len; staged_id=target_id; staged_seq=rollout_seq;   /* stage locally: a node never hears its own broadcast */
    memset(acked,0,sizeof acked); ack_n=0; ack_deadline_us=esp_timer_get_time()+(int64_t)ACK_WIN_MS*1000; coord=1;
    send_prepare(target_id,t,len,rollout_seq);
    emit("[%s] coord PREPARE seq=%u target=fusion-%s, collecting ACKs\r\n",my_label,rollout_seq,pname(target_id));
}

static int8_t read_own_band(void){
    if(my_kind==KIND_POT){ int raw=0; adc_oneshot_read(adc1,POT_ADC_CHAN,&raw); return project_pot(raw); }
    if(my_kind==KIND_TOF){ if(!tof_ok) return 3; return project_tof(read_range_single(&tof)); }
    return 3;
}

static void led_setup(void){ gpio_config_t g={ .pin_bit_mask=(1ULL<<LED_GPIO), .mode=GPIO_MODE_OUTPUT }; gpio_config(&g); gpio_set_level(LED_GPIO,0); }

void app_main(void){
    /* own UART0 for a clean binary-free status channel */
    const uart_config_t uc={ .baud_rate=115200,.data_bits=UART_DATA_8_BITS,.parity=UART_PARITY_DISABLE,.stop_bits=UART_STOP_BITS_1,.flow_ctrl=UART_HW_FLOWCTRL_DISABLE,.source_clk=UART_SCLK_DEFAULT };
    uart_driver_install(UART,1024,0,0,NULL,0); uart_param_config(UART,&uc); uart_set_pin(UART,1,3,UART_PIN_NO_CHANGE,UART_PIN_NO_CHANGE);

    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc=WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA,mac);

    /* self-select role from the baked MAC map */
    for(int i=0;i<ROLES_N;i++) if(memcmp(mac,ROLES[i].mac,6)==0){ my_slot=ROLES[i].slot; my_kind=ROLES[i].kind; my_label=ROLES[i].label; break; }
    if(my_slot==0xFF){ emit("node %02x:%02x:%02x:%02x:%02x:%02x has NO role in ROLES[] — idle\r\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]); for(;;) vTaskDelay(pdMS_TO_TICKS(1000)); }

    esp_now_init(); esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer={0}; memcpy(peer.peer_addr,BCAST,6); peer.ifidx=WIFI_IF_STA; peer.channel=0; peer.encrypt=false; esp_now_add_peer(&peer);
    rxq=xQueueCreate(16,sizeof(rxmsg_t));

    /* load + parse policy A as the active fusion table (B is the pre-vetted swap target) */
    node_id=mac[5];
    if(FUSE_TABLE_A_LEN>TBL_MAX){ emit("[%s] fusion table too large\r\n",my_label); for(;;) vTaskDelay(pdMS_TO_TICKS(1000)); }
    memcpy(tbl,FUSE_TABLE_A,FUSE_TABLE_A_LEN); uint8_t rc=parse_table(FUSE_TABLE_A_LEN); active_id=POLICY_ID_A;
    if(rc){ emit("[%s] fusion table parse FAILED rc=%u\r\n",my_label,rc); for(;;) vTaskDelay(pdMS_TO_TICKS(1000)); }

    led_setup();
    /* bring up this node's sensor */
    if(my_kind==KIND_POT){
        adc_oneshot_unit_init_cfg_t u1={ .unit_id=POT_ADC_UNIT };
        adc_oneshot_new_unit(&u1,&adc1);
        adc_oneshot_chan_cfg_t c={ .atten=ADC_ATTEN_DB_12, .bitwidth=ADC_BITWIDTH_12 };
        adc_oneshot_config_channel(adc1,POT_ADC_CHAN,&c);
    } else {
        i2c_config_t conf={ .mode=I2C_MODE_MASTER,.sda_io_num=SDA_GPIO,.scl_io_num=SCL_GPIO,.sda_pullup_en=GPIO_PULLUP_ENABLE,.scl_pullup_en=GPIO_PULLUP_ENABLE,.master.clk_speed=I2C_HZ };
        i2c_param_config(I2C_PORT,&conf); i2c_driver_install(I2C_PORT,I2C_MODE_MASTER,0,0,0);
        for(int a=0;a<3 && !tof_ok;a++){ tof_ok=vl53l0x_init(&tof,TOF_ADDR); if(!tof_ok) vTaskDelay(pdMS_TO_TICKS(50)); }
        if(!tof_ok) emit("[%s] VL53L0X init FAILED — this node will report band 3 (far)\r\n",my_label);
    }

    for(int i=0;i<N_SLOTS;i++){ bands[i]=-1; band_seen_us[i]=0; }
    emit("node %02x (%s) up — slot=%u kind=%s active=fusion-%s, mesh ready ('R' swaps rule; band 8 = sensor dark)\r\n",mac[5],my_label,my_slot,my_kind==KIND_TOF?"TOF":"POT",pname(active_id));

    uint16_t seq=0; int64_t next_bcast=0; bool warn_phase=false;
    for(;;){
        int64_t now=esp_timer_get_time();
        /* USB commands: 'R' swaps the fusion rule; a digit d sets simulated interference to d*10% drop; 'X' = blackout */
        uint8_t c;
        if(uart_read_bytes(UART,&c,1,0)==1){
            if(c=='R'||c=='r') start_rollout();
            else if(c>='0'&&c<='9'){ drop_pct=(uint8_t)((c-'0')*10); emit("[%s] interference: dropping %u%% of received verdicts\r\n",my_label,drop_pct); }
            else if(c=='X'||c=='x'){ drop_pct=99; emit("[%s] interference: near-total blackout (99%% drop)\r\n",my_label); }
        }
        /* drain ESP-NOW: sensor bands (continuous) + the two-phase swap of the fusion rule */
        rxmsg_t m;
        while(xQueueReceive(rxq,&m,0)==pdTRUE){
            uint8_t type=m.d[0];
            if(type==M_VERDICT && m.len>=3){
                if(drop_pct && (esp_random()%100)<drop_pct){ /* dropped by simulated interference */ }
                else { uint8_t slot=m.d[1]; int8_t band=(int8_t)m.d[2]; if(slot<N_SLOTS){ bands[slot]=band; band_seen_us[slot]=now; } } }
            else if(type==M_PREPARE && m.len>=10){ uint16_t sq=m.d[1]|(m.d[2]<<8); uint32_t id; memcpy(&id,m.d+3,4); uint16_t len=m.d[7]|(m.d[8]<<8);
                if(len<=TBL_MAX && 9+len<=m.len){ const uint8_t *t=m.d+9; uint32_t got=fnv1a32(t,len);
                    if(got==id && (id==POLICY_ID_A||id==POLICY_ID_B)){ memcpy(staged,t,len); staged_len=len; staged_id=id; staged_seq=sq; send_ack(sq);
                        emit("[%s] PREPARE ok seq=%u fusion-%s staged, ACK\r\n",my_label,sq,pname(id)); }
                    else emit("[%s] PREPARE REJECT seq=%u (hash/allowlist mismatch)\r\n",my_label,sq); } }
            else if(type==M_ACK && m.len>=4 && coord){ uint16_t sq=m.d[1]|(m.d[2]<<8); uint8_t nid=m.d[3];
                if(sq==rollout_seq && !acked[nid]){ acked[nid]=1; ack_n++; emit("[%s] coord ACK from %02x (%d/%d)\r\n",my_label,nid,ack_n,EXPECT_ACKS); } }
            else if(type==M_COMMIT && m.len>=5){ uint16_t sq=m.d[1]|(m.d[2]<<8); uint16_t delay=m.d[3]|(m.d[4]<<8);
                if(sq==staged_seq){ flip_at_us=esp_timer_get_time()+(int64_t)delay*1000; emit("[%s] COMMIT seq=%u flip in %ums\r\n",my_label,sq,delay); } }
        }
        /* coordinator: close the ACK window -> COMMIT on quorum, else ABORT (fleet stays put) */
        if(coord && ack_deadline_us && now>=ack_deadline_us){ ack_deadline_us=0;
            if(ack_n>=EXPECT_ACKS){ send_commit(rollout_seq,FLIP_DELAY); flip_at_us=esp_timer_get_time()+(int64_t)FLIP_DELAY*1000; emit("[%s] coord %d ACKs COMMIT seq=%u flip in %ums\r\n",my_label,ack_n,rollout_seq,FLIP_DELAY); }
            else emit("[%s] coord ABORT seq=%u only %d/%d, fleet stays on fusion-%s\r\n",my_label,rollout_seq,ack_n,EXPECT_ACKS,pname(active_id));
            coord=0;
        }
        /* the atomic fusion-rule flip: every node applies the staged rule at its own local tick */
        if(flip_at_us && now>=flip_at_us){ flip_at_us=0; set_active(staged,staged_len,staged_id); epoch++;
            emit(">>> FLIP %s -> fusion policy %s epoch=%lu <<<\r\n",my_label,pname(active_id),(unsigned long)epoch); }
        /* sense + broadcast + re-fuse on the cadence */
        if(now>=next_bcast){ next_bcast=now+BCAST_MS*1000;
            int8_t own=read_own_band(); bands[my_slot]=own; band_seen_us[my_slot]=esp_timer_get_time();
            send_verdict(my_slot,own,++seq);
            /* fail-operational: a slot we have not heard within STALE_MS reads the STALE sentinel, a
               first-class decidable band. The signed table escalates (TAMPER) or degrades on it, never
               blanks, so a dropped node localizes the fault instead of silencing the fleet. */
            int8_t in[N_SLOTS];
            memset(regs,0,sizeof regs);
            for(int i=0;i<N_SLOTS;i++){
                in[i] = (bands[i]>=0 && (now-band_seen_us[i])<(int64_t)STALE_MS*1000) ? bands[i] : (int8_t)STALE_BAND;
                wr32(regs+4+8*i,TY_INT); wr32(regs+8+8*i,in[i]);
            }
            uint8_t err=0; int8_t edge=evaluate(0,&err);
            const char *posture=(err||edge<0||edge>=VERDICTS_N)?"?":VERDICTS[edge];
            /* onboard LED: CRITICAL/TAMPER solid, DEGRADED/WARN blink, OK off — identical on every node */
            int lv; if(!strcmp(posture,"CRITICAL")||!strcmp(posture,"TAMPER")) lv=1;
            else if(!strcmp(posture,"DEGRADED")||!strcmp(posture,"WARN")){ warn_phase=!warn_phase; lv=warn_phase; } else lv=0;
            gpio_set_level(LED_GPIO,lv);
            emit("[%s] pol=%s a=%d b=%d arm=%d -> %s\r\n",my_label,pname(active_id),in[0],in[1],in[2],posture);
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
