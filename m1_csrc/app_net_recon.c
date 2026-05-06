/* See COPYING.txt for license details. */

/*
*
* app_net_recon.c
*
* Net Recon: TCP/IP network reconnaissance.
*
* Uses the ESP32-C6 AT firmware as the network stack:
*   - AT+CIPSTA?  -> read M1's local IP / gateway / netmask
*   - AT+PING     -> ICMP ping sweep
*   - AT+CIPSTART -> TCP port probe
*
* Three tabs accessed via LEFT/RIGHT:
*   Tab 0 : ARP-style ping sweep of the local /24
*   Tab 1 : Port scan of a user-entered IPv4 address (top-20 services)
*   Tab 2 : OUI / MAC vendor lookup against a built-in vendor table
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_net_recon.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "ctrl_api.h"
#include "m1_wifi.h"

#ifdef M1_APP_NET_RECON_ENABLE

/*************************** D E F I N E S ************************************/

#define NR_AT_BUF_SIZE        512

#define NR_TAB_ARP            0
#define NR_TAB_PORTS          1
#define NR_TAB_OUI            2
#define NR_TAB_COUNT          3

#define NR_MAX_HOSTS          64
#define NR_LIST_VISIBLE       4
#define NR_PORT_LIST_VISIBLE  4

#define NR_PING_TIMEOUT_S     2
#define NR_TCP_TIMEOUT_S      3

/*************************** S T R U C T U R E S *****************************/

typedef struct {
    uint8_t  octet4;       /* last byte of /24, 1..254 */
    bool     is_gateway;
    int16_t  rtt_ms;       /* -1 if unknown */
} nr_host_t;

typedef struct {
    uint16_t port;
    const char *name;
} nr_port_t;

typedef struct {
    uint32_t oui24;        /* MS 24 bits of MAC (e.g. 0xFC3D93) */
    const char *vendor;
} nr_oui_t;

/***************************** V A R I A B L E S ******************************/

/* Top-30 services to probe in port scan.  audit 07 / 04 — original list
 * missed several modern IoT-default ports (5000 UPnP, 8000 / 8888 HTTP-alt,
 * 631 IPP printers, 1883 / 8883 MQTT, 9100 raw print, 5353 mDNS, 1900 SSDP,
 * 139 NetBIOS).  Order is roughly "likely-positive first" so an early hit
 * shortens the worst case for an aborted scan. */
static const nr_port_t s_nr_ports[] = {
    {    80, "HTTP"     },
    {   443, "HTTPS"    },
    {    22, "SSH"      },
    {    23, "Telnet"   },
    {    21, "FTP"      },
    {    53, "DNS"      },
    {    25, "SMTP"     },
    {   110, "POP3"     },
    {   143, "IMAP"     },
    {   445, "SMB"      },
    {   139, "NetBIOS"  },
    {  3389, "RDP"      },
    {  5900, "VNC"      },
    {  3306, "MySQL"    },
    {  5432, "Postgres" },
    {  1433, "MSSQL"    },
    {  6379, "Redis"    },
    { 27017, "MongoDB"  },
    {  9200, "Elastic"  },
    {  8080, "HTTP-Alt" },
    {  8000, "HTTP-Dev" },
    {  8443, "HTTPS-Alt"},
    {  8888, "HTTP-Adm" },
    {  5000, "UPnP/Dev" },
    {   631, "IPP/Print"},
    {  9100, "RawPrint" },
    {  1883, "MQTT"     },
    {  8883, "MQTT-TLS" },
    {  5353, "mDNS"     },
    {  1900, "SSDP"     },
};
#define NR_PORT_COUNT ((uint8_t)(sizeof(s_nr_ports) / sizeof(s_nr_ports[0])))

/* OUI table.  Sorted ascending so a binary search would work, but a
 * linear scan is plenty quick for ~50 entries. */
static const nr_oui_t s_nr_ouis[] = {
    { 0x000000, "Xerox"            },
    { 0x000C29, "VMware"           },
    { 0x000D3A, "Microsoft"        },
    { 0x000E08, "Cisco"            },
    { 0x001A11, "Google (Nest)"    },
    { 0x001CB3, "Apple"            },
    { 0x001D0F, "TP-Link"          },
    { 0x001E58, "D-Link"           },
    { 0x002241, "Apple"            },
    { 0x0050BA, "D-Link"           },
    { 0x0050F2, "Microsoft"        },
    { 0x00A040, "Apple"            },
    { 0x00B600, "Schneider"        },
    { 0x00E0FC, "Huawei"           },
    { 0x080027, "VirtualBox"       },
    { 0x18B4D7, "Nest"             },
    { 0x1C1B0D, "Apple"            },
    { 0x1C9148, "Cisco"            },
    { 0x28E14C, "Apple"            },
    { 0x3C5A37, "Google"           },
    { 0x3CD92B, "HP"               },
    { 0x3CFDFE, "Intel"            },
    { 0x44650D, "Amazon"           },
    { 0x4C8D79, "Apple"            },
    { 0x5254AB, "QEMU/Realtek"     },
    { 0x5404A6, "ASUSTek"          },
    { 0x70588B, "Apple"            },
    { 0x70B3D5, "IEEE Reg"         },
    { 0x74D02B, "ASUSTek"          },
    { 0x7C4A82, "Sonos"            },
    { 0x84D81B, "Cisco"            },
    { 0x8C8590, "Apple"            },
    { 0x9027E4, "Apple"            },
    { 0x9457A5, "Liteon"           },
    { 0x98DED0, "TP-Link"          },
    { 0x9CB6D0, "Rivet Networks"   },
    { 0xA45D36, "Hewlett Packard"  },
    { 0xA4C3F0, "Apple"            },
    { 0xA8BD27, "Apple"            },
    { 0xAC18D6, "Sonos"            },
    { 0xB827EB, "Raspberry Pi"     },
    { 0xC83A35, "Tenda"            },
    { 0xCC6B1E, "Bosch"            },
    { 0xD85D4C, "Samsung"          },
    { 0xDC2B2A, "Apple"            },
    { 0xE0286D, "Apple"            },
    { 0xE0B52D, "Apple"            },
    { 0xE45F01, "Raspberry Pi"     },
    { 0xF0F61C, "Apple"            },
    { 0xF4F5E8, "Google"           },
    { 0xFC3D93, "Apple"            },
    { 0xFCFC48, "Apple"            },
};
#define NR_OUI_COUNT ((uint16_t)(sizeof(s_nr_ouis) / sizeof(s_nr_ouis[0])))

static char s_nr_at_buf[NR_AT_BUF_SIZE];

/* Tab 0 (ARP) state */
static nr_host_t s_nr_hosts[NR_MAX_HOSTS];
static uint8_t   s_nr_host_count;
static uint8_t   s_nr_subnet[3];        /* {a,b,c} of a.b.c.0/24 */
static uint8_t   s_nr_gw_octet4;
static char      s_nr_my_ip_str[20];

/* Tab 1 (port scan) state */
static uint8_t   s_nr_target[4]   = { 192, 168, 1, 1 };
static uint8_t   s_nr_target_idx;        /* 0..3 octet cursor */
static bool      s_nr_port_open[NR_PORT_COUNT];
static uint8_t   s_nr_port_progress;
static bool      s_nr_port_scanned;

/* Tab 2 (OUI) state */
static uint8_t   s_nr_mac[6]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t   s_nr_mac_nibble;        /* 0..11 cursor across 12 nibbles */

/* Tab loops report back which navigation action ended them. */
typedef enum {
    NR_NAV_EXIT = 0,
    NR_NAV_PREV,
    NR_NAV_NEXT
} nr_nav_t;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static void nr_display_msg(const char *line1, const char *line2);
static bool nr_get_local_ip(void);
static bool nr_at_ping(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int *rtt_ms);
static bool nr_at_tcp_probe(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                            uint16_t port);
static const char *nr_oui_lookup(uint32_t oui24);

static void    nr_arp_scan(void);
static void    nr_arp_draw(uint8_t scroll, uint8_t sel, bool scanning,
                           uint16_t progress);
static nr_nav_t nr_arp_loop(void);
static nr_nav_t nr_ports_loop(void);
static void    nr_ports_draw_setup(void);
static void    nr_ports_draw_results(uint8_t scroll, uint8_t sel);
static void    nr_ports_run_scan(void);
static nr_nav_t nr_oui_loop(void);
static void    nr_oui_draw(void);

/*============================================================================*/
/**
  * @brief Display two-line status panel
  */
/*============================================================================*/
static void nr_display_msg(const char *line1, const char *line2)
{
    m1_u8g2_firstpage();
    m1_draw_status_panel(&m1_u8g2, "Net Recon", NULL, NULL, 0, 0,
                         line1, line2, NULL);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Pull our local IP from `AT+CIPSTA?` and split into subnet + last
  *        octet.
  */
/*============================================================================*/
static bool nr_get_local_ip(void)
{
    char *p;
    int a, b, c, d;
    int g1, g2, g3, g4;
    bool got_ip = false;
    bool got_gw = false;

    s_nr_my_ip_str[0] = '\0';
    if (spi_AT_send_recv("AT+CIPSTA?\r\n",
                         s_nr_at_buf, sizeof(s_nr_at_buf), 3) != SUCCESS)
        return false;

    /* +CIPSTA:ip:"192.168.1.100"
     * +CIPSTA:gateway:"192.168.1.1"
     * +CIPSTA:netmask:"255.255.255.0" */
    p = strstr(s_nr_at_buf, "ip:\"");
    if (p && sscanf(p, "ip:\"%d.%d.%d.%d\"", &a, &b, &c, &d) == 4 &&
        a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
        c >= 0 && c <= 255 && d >= 0 && d <= 255)
    {
        s_nr_subnet[0] = (uint8_t)a;
        s_nr_subnet[1] = (uint8_t)b;
        s_nr_subnet[2] = (uint8_t)c;
        snprintf(s_nr_my_ip_str, sizeof(s_nr_my_ip_str),
                 "%d.%d.%d.%d", a, b, c, d);
        got_ip = true;

        /* Pre-fill the port-scan target with our gateway-style first guess */
        s_nr_target[0] = (uint8_t)a;
        s_nr_target[1] = (uint8_t)b;
        s_nr_target[2] = (uint8_t)c;
        if (s_nr_target[3] == 0) s_nr_target[3] = 1;
    }

    p = strstr(s_nr_at_buf, "gateway:\"");
    if (p && sscanf(p, "gateway:\"%d.%d.%d.%d\"", &g1, &g2, &g3, &g4) == 4 &&
        g4 >= 0 && g4 <= 255)
    {
        s_nr_gw_octet4 = (uint8_t)g4;
        got_gw = true;
    }
    else
    {
        s_nr_gw_octet4 = 1;     /* sane default */
    }

    (void)got_gw;
    return got_ip;
}

/*============================================================================*/
/**
  * @brief Issue an `AT+PING` to the given IP, reporting RTT in ms.
  *
  * Returns true if a non-timeout response came back.
  */
/*============================================================================*/
static bool nr_at_ping(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int *rtt_ms)
{
    char cmd[48];
    char *p;
    int v;

    if (rtt_ms) *rtt_ms = -1;

    snprintf(cmd, sizeof(cmd), "AT+PING=\"%u.%u.%u.%u\"\r\n",
             (unsigned)a, (unsigned)b, (unsigned)c, (unsigned)d);

    if (spi_AT_send_recv(cmd, s_nr_at_buf, sizeof(s_nr_at_buf),
                         NR_PING_TIMEOUT_S) != SUCCESS)
        return false;

    /* On success the AT firmware returns "+PING:<ms>\r\n\r\nOK\r\n",
     * on failure "+PING:TIMEOUT" or "+PING:-1". */
    if (strstr(s_nr_at_buf, "TIMEOUT") || strstr(s_nr_at_buf, ":-1"))
        return false;

    p = strstr(s_nr_at_buf, "+PING:");
    if (!p) return false;

    if (sscanf(p, "+PING:%d", &v) == 1 && v >= 0)
    {
        if (rtt_ms) *rtt_ms = v;
        return true;
    }

    /* If +PING was returned but we couldn't parse, treat OK as success */
    return (strstr(s_nr_at_buf, "\r\nOK\r\n") != NULL);
}

/*============================================================================*/
/**
  * @brief Try to TCP-connect to host:port, then immediately close.
  *        Returns true if the connect succeeded ("CONNECT" reported).
  */
/*============================================================================*/
static bool nr_at_tcp_probe(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                            uint16_t port)
{
    char cmd[64];
    bool open = false;

    /* Single-connection mode for the probe. */
    spi_AT_send_recv("AT+CIPMUX=0\r\n", s_nr_at_buf,
                     sizeof(s_nr_at_buf), 1);

    snprintf(cmd, sizeof(cmd),
             "AT+CIPSTART=\"TCP\",\"%u.%u.%u.%u\",%u,%u\r\n",
             (unsigned)a, (unsigned)b, (unsigned)c, (unsigned)d,
             (unsigned)port, (unsigned)NR_TCP_TIMEOUT_S);

    if (spi_AT_send_recv(cmd, s_nr_at_buf, sizeof(s_nr_at_buf),
                         NR_TCP_TIMEOUT_S + 1) == SUCCESS)
    {
        if (strstr(s_nr_at_buf, "CONNECT") &&
            !strstr(s_nr_at_buf, "ERROR")  &&
            !strstr(s_nr_at_buf, "FAIL")   &&
            !strstr(s_nr_at_buf, "CLOSED"))
        {
            open = true;
        }
        else if (strstr(s_nr_at_buf, "ALREADY CONNECTED"))
        {
            open = true;
        }
    }

    /* Always close so we can probe the next port */
    spi_AT_send_recv("AT+CIPCLOSE\r\n", s_nr_at_buf,
                     sizeof(s_nr_at_buf), 1);

    return open;
}

/*============================================================================*/
/**
  * @brief Linear OUI table lookup.
  */
/*============================================================================*/
static const char *nr_oui_lookup(uint32_t oui24)
{
    uint16_t i;
    for (i = 0; i < NR_OUI_COUNT; i++)
        if (s_nr_ouis[i].oui24 == oui24) return s_nr_ouis[i].vendor;
    return "Unknown";
}

/*============================================================================*/
/*                        TAB 0:  ARP / Ping Sweep                            */
/*============================================================================*/

/*============================================================================*/
/**
  * @brief Render the ARP-scan tab.
  */
/*============================================================================*/
static void nr_arp_draw(uint8_t scroll, uint8_t sel, bool scanning,
                        uint16_t progress)
{
    char hdr[12];
    uint8_t i;

    snprintf(hdr, sizeof(hdr), "[ARP]");

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_draw_header_bar(&m1_u8g2, "Net Recon", hdr);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    if (s_nr_my_ip_str[0])
    {
        char ipln[28];
        snprintf(ipln, sizeof(ipln), "Me:%s", s_nr_my_ip_str);
        m1_draw_text(&m1_u8g2, 2, 22, 124, ipln, TEXT_ALIGN_LEFT);
    }
    else
    {
        m1_draw_text(&m1_u8g2, 2, 22, 124,
                     "Connect to WiFi first",
                     TEXT_ALIGN_LEFT);
    }

    if (scanning)
    {
        char prog[24];
        snprintf(prog, sizeof(prog), "Scanning %u/254", (unsigned)progress);
        m1_draw_text(&m1_u8g2, 2, 30, 124, prog, TEXT_ALIGN_LEFT);
    }

    /* List rows */
    for (i = 0; i < NR_LIST_VISIBLE; i++)
    {
        uint8_t idx = scroll + i;
        char row[28];

        if (idx >= s_nr_host_count)
        {
            m1_draw_text(&m1_u8g2, 4, 38 + i * 7, 122, "", TEXT_ALIGN_LEFT);
            continue;
        }

        snprintf(row, sizeof(row), "%c %u.%u.%u.%-3u %s",
                 (idx == sel) ? '>' : ' ',
                 (unsigned)s_nr_subnet[0],
                 (unsigned)s_nr_subnet[1],
                 (unsigned)s_nr_subnet[2],
                 (unsigned)s_nr_hosts[idx].octet4,
                 s_nr_hosts[idx].is_gateway ? "[GW]" : "[UP]");
        m1_draw_text(&m1_u8g2, 2, 38 + i * 7, 124, row, TEXT_ALIGN_LEFT);
    }

    if (scanning)
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Stop", "L/R tabs", arrowright_8x8);
    else
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Scan", arrowright_8x8);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Run a /24 ping sweep, populating s_nr_hosts[].
  */
/*============================================================================*/
static void nr_arp_scan(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    uint8_t last;

    s_nr_host_count = 0;

    /* Re-read our IP every scan, in case wifi was just connected. */
    if (!nr_get_local_ip())
    {
        nr_display_msg("No IP", "Connect WiFi first");
        osDelay(1500);
        return;
    }

    for (last = 1; last <= 254; last++)
    {
        /* Allow user to bail early. */
        if (xQueueReceive(main_q_hdl, &q_item, 0) == pdTRUE &&
            q_item.q_evt_type == Q_EVENT_KEYPAD &&
            xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE)
        {
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
                break;
        }

        nr_arp_draw(0, 0, true, last);

        int rtt;
        if (nr_at_ping(s_nr_subnet[0], s_nr_subnet[1], s_nr_subnet[2],
                       last, &rtt))
        {
            if (s_nr_host_count < NR_MAX_HOSTS)
            {
                s_nr_hosts[s_nr_host_count].octet4 = last;
                s_nr_hosts[s_nr_host_count].is_gateway =
                    (last == s_nr_gw_octet4);
                s_nr_hosts[s_nr_host_count].rtt_ms = (int16_t)rtt;
                s_nr_host_count++;
            }
        }
    }
}

/*============================================================================*/
/**
  * @brief Tab 0 main loop.  Returns when user taps LEFT/RIGHT to switch
  *        tabs or BACK to exit.
  */
/*============================================================================*/
static nr_nav_t nr_arp_loop(void)
{
    /* Outer loop is owned by the caller; we just service this tab until
     * a tab-switch / back keystroke.  Caller will re-enter on next tab. */
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    uint8_t scroll = 0;
    uint8_t sel = 0;

    if (s_nr_my_ip_str[0] == '\0') nr_get_local_ip();

    nr_arp_draw(scroll, sel, false, 0);

    for (;;)
    {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &btn, 0);

        if (btn.event[BUTTON_BACK_KP_ID]  == BUTTON_EVENT_CLICK) return NR_NAV_EXIT;
        if (btn.event[BUTTON_LEFT_KP_ID]  == BUTTON_EVENT_CLICK) return NR_NAV_PREV;
        if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) return NR_NAV_NEXT;

        if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            nr_arp_scan();
            sel = 0;
            scroll = 0;
            xQueueReset(main_q_hdl);
        }
        else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (sel + 1 < s_nr_host_count) sel++;
            if (sel >= scroll + NR_LIST_VISIBLE) scroll = sel - NR_LIST_VISIBLE + 1;
        }
        else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (sel > 0) sel--;
            if (sel < scroll) scroll = sel;
        }
        nr_arp_draw(scroll, sel, false, 0);
    }
}

/*============================================================================*/
/*                          TAB 1: Port Scan                                  */
/*============================================================================*/

/*============================================================================*/
/**
  * @brief Render the port-scan setup screen with cursor on octet.
  */
/*============================================================================*/
static void nr_ports_draw_setup(void)
{
    char ip_line[32];
    char cur_line[32];
    uint8_t i;

    /* Build "192.168.001.001" with caret marker on the active octet. */
    snprintf(ip_line, sizeof(ip_line), "%3u.%3u.%3u.%3u",
             (unsigned)s_nr_target[0], (unsigned)s_nr_target[1],
             (unsigned)s_nr_target[2], (unsigned)s_nr_target[3]);

    memset(cur_line, ' ', sizeof(cur_line));
    cur_line[sizeof(cur_line) - 1] = '\0';
    for (i = 0; i < sizeof(cur_line) - 1; i++) cur_line[i] = ' ';
    if (s_nr_target_idx <= 3)
    {
        uint8_t pos = (uint8_t)(s_nr_target_idx * 4 + 1); /* between digits */
        if (pos < sizeof(cur_line) - 1) cur_line[pos] = '^';
    }
    cur_line[16] = '\0';

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_draw_header_bar(&m1_u8g2, "Net Recon", "[Ports]");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    m1_draw_text(&m1_u8g2, 2, 22, 124, "Target IP:", TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 12, 32, 116, ip_line, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 12, 40, 116, cur_line, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 2, 50, 124, "L/R octet UP/DN val",
                 TEXT_ALIGN_LEFT);

    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Scan", arrowright_8x8);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Render the port-scan results list.
  */
/*============================================================================*/
static void nr_ports_draw_results(uint8_t scroll, uint8_t sel)
{
    char hdr[16];
    uint8_t i;

    snprintf(hdr, sizeof(hdr), "[Ports %u/%u]",
             (unsigned)s_nr_port_progress, (unsigned)NR_PORT_COUNT);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_draw_header_bar(&m1_u8g2, "Net Recon", hdr);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    {
        char ip_line[24];
        snprintf(ip_line, sizeof(ip_line), "%u.%u.%u.%u",
                 (unsigned)s_nr_target[0], (unsigned)s_nr_target[1],
                 (unsigned)s_nr_target[2], (unsigned)s_nr_target[3]);
        m1_draw_text(&m1_u8g2, 2, 22, 124, ip_line, TEXT_ALIGN_LEFT);
    }

    for (i = 0; i < NR_PORT_LIST_VISIBLE; i++)
    {
        uint8_t idx = scroll + i;
        char row[28];

        if (idx >= NR_PORT_COUNT) break;

        snprintf(row, sizeof(row), "%c %5u %-9s %s",
                 (idx == sel) ? '>' : ' ',
                 (unsigned)s_nr_ports[idx].port,
                 s_nr_ports[idx].name,
                 (idx < s_nr_port_progress)
                     ? (s_nr_port_open[idx] ? "OPEN" : "----")
                     : "?");
        m1_draw_text(&m1_u8g2, 2, 32 + i * 7, 124, row, TEXT_ALIGN_LEFT);
    }

    if (s_nr_port_scanned)
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Re-scan", arrowright_8x8);
    else
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Edit IP", arrowright_8x8);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Run the full top-20 TCP port scan and update progress live.
  */
/*============================================================================*/
static void nr_ports_run_scan(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    uint8_t i;

    s_nr_port_scanned = false;
    s_nr_port_progress = 0;
    memset(s_nr_port_open, 0, sizeof(s_nr_port_open));

    for (i = 0; i < NR_PORT_COUNT; i++)
    {
        nr_ports_draw_results(0, i);

        s_nr_port_open[i] = nr_at_tcp_probe(s_nr_target[0], s_nr_target[1],
                                            s_nr_target[2], s_nr_target[3],
                                            s_nr_ports[i].port);
        s_nr_port_progress = i + 1;

        /* Allow early stop */
        if (xQueueReceive(main_q_hdl, &q_item, 0) == pdTRUE &&
            q_item.q_evt_type == Q_EVENT_KEYPAD &&
            xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE)
        {
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
                break;
        }
    }

    s_nr_port_scanned = true;
    nr_ports_draw_results(0, 0);
}

/*============================================================================*/
/**
  * @brief Tab 1 main loop.
  */
/*============================================================================*/
static nr_nav_t nr_ports_loop(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    bool editing = !s_nr_port_scanned;
    uint8_t scroll = 0, sel = 0;

    if (editing) nr_ports_draw_setup();
    else         nr_ports_draw_results(scroll, sel);

    for (;;)
    {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &btn, 0);

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) return NR_NAV_EXIT;

        if (editing)
        {
            if (btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (s_nr_target_idx > 0) s_nr_target_idx--;
                else return NR_NAV_PREV;
            }
            else if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (s_nr_target_idx < 3) s_nr_target_idx++;
                else return NR_NAV_NEXT;
            }
            else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                s_nr_target[s_nr_target_idx]++;
                /* uint8_t naturally wraps 255->0 */
            }
            else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                s_nr_target[s_nr_target_idx]--;
            }
            else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                nr_ports_run_scan();
                editing = false;
                xQueueReset(main_q_hdl);
            }
            nr_ports_draw_setup();
            if (!editing) nr_ports_draw_results(scroll, sel);
        }
        else
        {
            if (btn.event[BUTTON_LEFT_KP_ID]  == BUTTON_EVENT_CLICK) return NR_NAV_PREV;
            if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) return NR_NAV_NEXT;

            if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (sel > 0) sel--;
                if (sel < scroll) scroll = sel;
            }
            else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (sel + 1 < NR_PORT_COUNT) sel++;
                if (sel >= scroll + NR_PORT_LIST_VISIBLE)
                    scroll = sel - NR_PORT_LIST_VISIBLE + 1;
            }
            else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                editing = true;
                nr_ports_draw_setup();
                continue;
            }
            nr_ports_draw_results(scroll, sel);
        }
    }
}

/*============================================================================*/
/*                          TAB 2: OUI Lookup                                 */
/*============================================================================*/

/*============================================================================*/
/**
  * @brief Render the OUI tab with cursor on the active nibble.
  */
/*============================================================================*/
static void nr_oui_draw(void)
{
    char mac_line[24];
    char cur_line[24];
    uint32_t oui24;
    const char *vendor;
    uint8_t i;
    uint8_t pos;

    /* "AA:BB:CC:DD:EE:FF" */
    snprintf(mac_line, sizeof(mac_line),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             s_nr_mac[0], s_nr_mac[1], s_nr_mac[2],
             s_nr_mac[3], s_nr_mac[4], s_nr_mac[5]);

    memset(cur_line, ' ', sizeof(cur_line));
    cur_line[sizeof(cur_line) - 1] = '\0';
    for (i = 0; i < sizeof(cur_line) - 1; i++) cur_line[i] = ' ';
    /* nibble positions: 0,1 => bytes 0; 2,3 => bytes 1; ...; 10,11 => byte 5
     * within the colon-separated string, nibble n maps to display column
     *    (n / 2) * 3 + (n % 2)
     */
    pos = (uint8_t)((s_nr_mac_nibble / 2) * 3 + (s_nr_mac_nibble % 2));
    if (pos < sizeof(cur_line) - 1) cur_line[pos] = '^';
    cur_line[18] = '\0';

    oui24  = ((uint32_t)s_nr_mac[0] << 16) |
             ((uint32_t)s_nr_mac[1] << 8)  |
             (uint32_t)s_nr_mac[2];
    vendor = nr_oui_lookup(oui24);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_draw_header_bar(&m1_u8g2, "Net Recon", "[OUI]");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    m1_draw_text(&m1_u8g2, 2, 22, 124, "MAC:", TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 24, 22, 100, mac_line, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 24, 30, 100, cur_line, TEXT_ALIGN_LEFT);

    {
        char vline[28];
        snprintf(vline, sizeof(vline), "Vendor: %.16s", vendor);
        m1_draw_text(&m1_u8g2, 2, 42, 124, vline, TEXT_ALIGN_LEFT);
    }
    m1_draw_text(&m1_u8g2, 2, 50, 124, "L/R nibble UP/DN val",
                 TEXT_ALIGN_LEFT);

    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Tabs", arrowright_8x8);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Tab 2 main loop.
  */
/*============================================================================*/
static nr_nav_t nr_oui_loop(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;

    nr_oui_draw();

    for (;;)
    {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &btn, 0);

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) return NR_NAV_EXIT;

        if (btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (s_nr_mac_nibble > 0) s_nr_mac_nibble--;
            else return NR_NAV_PREV;
        }
        else if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (s_nr_mac_nibble < 11) s_nr_mac_nibble++;
            else return NR_NAV_NEXT;
        }
        else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK ||
                 btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            int8_t delta =
                (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK) ? +1 : -1;
            uint8_t byte_idx = (uint8_t)(s_nr_mac_nibble / 2);
            bool high = ((s_nr_mac_nibble % 2) == 0);
            uint8_t hi = (uint8_t)((s_nr_mac[byte_idx] >> 4) & 0x0F);
            uint8_t lo = (uint8_t)(s_nr_mac[byte_idx] & 0x0F);

            if (high) hi = (uint8_t)((hi + delta + 16) & 0x0F);
            else      lo = (uint8_t)((lo + delta + 16) & 0x0F);

            s_nr_mac[byte_idx] = (uint8_t)((hi << 4) | lo);
        }
        nr_oui_draw();
    }
}

/*============================================================================*/
/*                              Top-level entry                                */
/*============================================================================*/

/*============================================================================*/
/**
  * @brief Public entry point.  Manages the tab carousel.
  */
/*============================================================================*/
void app_net_recon_run(void)
{
    uint8_t tab = NR_TAB_ARP;

    /* Make sure ESP32 stack is up. */
    if (!m1_esp32_get_init_status())
        m1_esp32_init();
    if (!get_esp32_main_init_status())
    {
        nr_display_msg("Initializing", "ESP32-C6...");
        esp32_main_init();
    }
    if (!get_esp32_main_init_status())
    {
        nr_display_msg("ESP32", "not ready!");
        osDelay(2000);
        return;
    }

    /* For ARP / port-scan we want WiFi STA association.  If not connected
     * we still allow the OUI tab to work - that is purely offline. */
    if (!wifi_is_connected())
    {
        nr_display_msg("WiFi not", "connected!");
        osDelay(1500);
        /* Don't return - OUI tab works offline, and reconnect may happen */
    }

    /* Snapshot our IP + gateway up front so the user sees something fresh. */
    nr_get_local_ip();

    /* Tab carousel: each tab loop returns NR_NAV_EXIT to leave the app,
     * NR_NAV_NEXT to advance to the next tab, NR_NAV_PREV to go back. */
    for (;;)
    {
        nr_nav_t nav;

        switch (tab)
        {
            case NR_TAB_ARP:    nav = nr_arp_loop();   break;
            case NR_TAB_PORTS:  nav = nr_ports_loop(); break;
            case NR_TAB_OUI:    nav = nr_oui_loop();   break;
            default:            tab = NR_TAB_ARP; continue;
        }

        if (nav == NR_NAV_EXIT)
        {
            xQueueReset(main_q_hdl);
            return;
        }
        else if (nav == NR_NAV_PREV)
        {
            tab = (uint8_t)((tab == 0) ? (NR_TAB_COUNT - 1) : (tab - 1));
        }
        else /* NR_NAV_NEXT */
        {
            tab = (uint8_t)((tab + 1U) % NR_TAB_COUNT);
        }

        xQueueReset(main_q_hdl);
    }
}

#endif /* M1_APP_NET_RECON_ENABLE */
