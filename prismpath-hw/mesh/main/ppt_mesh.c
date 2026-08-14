/* ppt_mesh.c — coordinated Level M policy hot-swap across an ESP-NOW mesh of ESP32 nodes.
 *
 * The physical realization of the crypto-migration fleet model (#94): every node holds two
 * pre-vetted policies (A permissive, B tightened; tables.h). A node poked with 'R' over USB becomes
 * the COORDINATOR for one rollout and runs a two-phase commit over ESP-NOW:
 *   1. PREPARE  — broadcast the target policy bytes + its id. Followers verify the id is on the
 *                 allowlist {A,B} (the on-device "pre-vetting"), stage it, and ACK.
 *   2. COMMIT   — once all followers ACK (else ABORT — all-or-nothing), broadcast "flip in Δ ms".
 *                Every node flips its active policy at local_now+Δ, so they transition together
 *                (within ESP-NOW delivery jitter, ~ms). The flip itself is a single pointer swap.
 * Each node continuously evaluates the SAME signed .ppt every substrate certifies, on a fixed test
 * input, and reports its verdict over USB — so the host sees all three flip allow<->deny at once.
 *
 * (The id-allowlist stands in for an Ed25519 signature check — the same shape, next layer up.)
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
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
#include "tables.h"

#define UART        UART_NUM_0
#define TBL_MAX     640
#define REGS_MAX    (4 + 8 * 24)
#define STACK_MAX   64
#define EXPECT_ACKS 2          /* 3-node fleet -> coordinator waits for the other two */
#define ACK_WIN_MS  500
#define FLIP_DELAY  120        /* ms from COMMIT receipt to the atomic flip */

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { M_PREPARE = 1, M_ACK = 2, M_COMMIT = 3 };
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ---------------- evaluator core (interp.c, byte-exact) ---------------- */
static uint8_t tbl[TBL_MAX], regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_base;
static uint16_t rd16(const uint8_t *p){ return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static int32_t rd32(const uint8_t *p){ int32_t v; memcpy(&v,p,4); return v; }
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

/* ---------------- state ---------------- */
static uint32_t active_id;
static uint8_t staged[TBL_MAX]; static uint16_t staged_len; static uint32_t staged_id; static uint16_t staged_seq;
static volatile int64_t flip_at_us = 0; static uint32_t epoch = 0; static uint8_t node_id;
/* coordinator */
static int coord = 0; static uint16_t rollout_seq = 0; static int64_t ack_deadline_us = 0; static uint8_t acked[256]; static int ack_n = 0;

static void set_active(const uint8_t *t,uint16_t len,uint32_t id){ memcpy(tbl,t,len); parse_table(len); active_id=id; }
static const char* pname(uint32_t id){ return id==POLICY_ID_A?"A":(id==POLICY_ID_B?"B":"?"); }

/* ---------------- UART I/O (own UART0, console disabled) ---------------- */
static void emit(const char *fmt,...){ char b[160]; va_list ap; va_start(ap,fmt); int n=vsnprintf(b,sizeof b,fmt,ap); va_end(ap); if(n>0) uart_write_bytes(UART,b,n); }
static QueueHandle_t rxq;
typedef struct { uint8_t src[6]; int len; uint8_t d[TBL_MAX+16]; } rxmsg_t;
static void on_recv(const esp_now_recv_info_t *info,const uint8_t *data,int len){ if(len>(int)sizeof(((rxmsg_t*)0)->d)) return; rxmsg_t m; memcpy(m.src,info->src_addr,6); m.len=len; memcpy(m.d,data,len); xQueueSend(rxq,&m,0); }

static void bcast(const uint8_t *d,int n){ esp_now_send(BCAST,d,n); }
static void send_prepare(uint32_t id,const uint8_t *t,uint16_t len,uint16_t seq){ uint8_t b[TBL_MAX+16]; int p=0; b[p++]=M_PREPARE; b[p++]=seq&0xFF; b[p++]=seq>>8; memcpy(b+p,&id,4); p+=4; b[p++]=len&0xFF; b[p++]=len>>8; memcpy(b+p,t,len); p+=len; bcast(b,p); }
static void send_ack(uint16_t seq){ uint8_t b[4]={M_ACK,seq&0xFF,seq>>8,node_id}; bcast(b,4); }
static void send_commit(uint16_t seq,uint16_t delay){ uint8_t b[5]={M_COMMIT,seq&0xFF,seq>>8,delay&0xFF,delay>>8}; bcast(b,5); }

static int verdict(void){ uint8_t err=0; int8_t e=evaluate(0,&err); return e; }

static void start_rollout(void){
    uint32_t target_id = (active_id==POLICY_ID_A)?POLICY_ID_B:POLICY_ID_A;
    const uint8_t *t = (target_id==POLICY_ID_A)?TABLE_A:TABLE_B; uint16_t len=(target_id==POLICY_ID_A)?TABLE_A_LEN:TABLE_B_LEN;
    rollout_seq++;
    /* stage locally (a node never hears its own broadcast) */
    memcpy(staged,t,len); staged_len=len; staged_id=target_id; staged_seq=rollout_seq;
    memset(acked,0,sizeof acked); ack_n=0; ack_deadline_us=esp_timer_get_time()+(int64_t)ACK_WIN_MS*1000;
    coord=1;
    send_prepare(target_id,t,len,rollout_seq);
    emit("[coord] PREPARE seq=%u target=%s(%08lx) — collecting ACKs\r\n",rollout_seq,pname(target_id),(unsigned long)target_id);
}

void app_main(void){
    /* own UART0 for the binary-free status/command channel */
    const uart_config_t uc={ .baud_rate=115200,.data_bits=UART_DATA_8_BITS,.parity=UART_PARITY_DISABLE,.stop_bits=UART_STOP_BITS_1,.flow_ctrl=UART_HW_FLOWCTRL_DISABLE,.source_clk=UART_SCLK_DEFAULT };
    uart_driver_install(UART,1024,0,0,NULL,0); uart_param_config(UART,&uc); uart_set_pin(UART,1,3,UART_PIN_NO_CHANGE,UART_PIN_NO_CHANGE);

    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc=WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA,mac); node_id=mac[5];
    esp_now_init(); esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer={0}; memcpy(peer.peer_addr,BCAST,6); peer.ifidx=WIFI_IF_STA; peer.channel=0; peer.encrypt=false; esp_now_add_peer(&peer);
    rxq=xQueueCreate(8,sizeof(rxmsg_t));

    set_active(TABLE_A,TABLE_A_LEN,POLICY_ID_A);
    memset(regs,0,sizeof regs); regs[4]=TY_INT; memcpy(regs+8,&TEST_LEVEL,4);
    emit("node %02x up (mac %02x:%02x:%02x:%02x:%02x:%02x) — active=%s verdict=%s\r\n",node_id,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],pname(active_id),verdict()==0?"ALLOW":"DENY");

    int64_t next_status=0;
    for(;;){
        int64_t now=esp_timer_get_time();
        /* USB command: 'R' -> initiate a rollout (toggle the fleet's policy) */
        uint8_t c; if(uart_read_bytes(UART,&c,1,0)==1 && (c=='R'||c=='r')) start_rollout();
        /* ESP-NOW messages */
        rxmsg_t m;
        while(xQueueReceive(rxq,&m,0)==pdTRUE){
            uint8_t type=m.d[0];
            if(type==M_PREPARE && m.len>=10){ uint16_t seq=m.d[1]|(m.d[2]<<8); uint32_t id; memcpy(&id,m.d+3,4); uint16_t len=m.d[7]|(m.d[8]<<8);
                if(len<=TBL_MAX && 9+len<=m.len){ const uint8_t *t=m.d+9; uint32_t got=fnv1a32(t,len);
                    if(got==id && (id==POLICY_ID_A||id==POLICY_ID_B)){ memcpy(staged,t,len); staged_len=len; staged_id=id; staged_seq=seq; send_ack(seq);
                        emit("  PREPARE ok seq=%u %s(%08lx) staged — ACK\r\n",seq,pname(id),(unsigned long)id); }
                    else emit("  PREPARE REJECT seq=%u id=%08lx (not on allowlist / hash mismatch)\r\n",seq,(unsigned long)id); } }
            else if(type==M_ACK && m.len>=4 && coord){ uint16_t seq=m.d[1]|(m.d[2]<<8); uint8_t nid=m.d[3];
                if(seq==rollout_seq && !acked[nid]){ acked[nid]=1; ack_n++; emit("  [coord] ACK from %02x (%d/%d)\r\n",nid,ack_n,EXPECT_ACKS); } }
            else if(type==M_COMMIT && m.len>=5){ uint16_t seq=m.d[1]|(m.d[2]<<8); uint16_t delay=m.d[3]|(m.d[4]<<8);
                if(seq==staged_seq){ flip_at_us=esp_timer_get_time()+(int64_t)delay*1000; emit("  COMMIT seq=%u -> flip in %ums\r\n",seq,delay); } }
        }
        /* coordinator: close the ACK window */
        if(coord && ack_deadline_us && now>=ack_deadline_us){
            ack_deadline_us=0;
            if(ack_n>=EXPECT_ACKS){ send_commit(rollout_seq,FLIP_DELAY); flip_at_us=esp_timer_get_time()+(int64_t)FLIP_DELAY*1000; emit("[coord] %d ACKs — COMMIT seq=%u, flip in %ums\r\n",ack_n,rollout_seq,FLIP_DELAY); }
            else emit("[coord] ABORT seq=%u — only %d/%d staged, fleet stays on %s\r\n",rollout_seq,ack_n,EXPECT_ACKS,pname(active_id));
            coord=0;
        }
        /* the atomic flip */
        if(flip_at_us && now>=flip_at_us){ flip_at_us=0; set_active(staged,staged_len,staged_id); epoch++;
            emit(">>> FLIP node=%02x -> policy %s verdict=%s epoch=%lu <<<\r\n",node_id,pname(active_id),verdict()==0?"ALLOW":"DENY",(unsigned long)epoch); }
        /* heartbeat status */
        if(now>=next_status){ next_status=now+700000; emit("node=%02x active=%s verdict=%s epoch=%lu\r\n",node_id,pname(active_id),verdict()==0?"ALLOW":"DENY",(unsigned long)epoch); }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
