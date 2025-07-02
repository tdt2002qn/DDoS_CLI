#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <i2c1602.h>
#include <pthread.h>
#include <wiringPi.h>
#include <wiringPiI2C.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <ncurses.h>
#include <curses.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <glib.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
// sudo apt-get install libcurl4-openssl-dev libcjson-dev
typedef struct
{
  char interface_name[20];
  int is_mirroring;
  int monitor_target_id; // InterfaceToMonitorInterfaceId
  char mirror_setting[20];
  char mirror_type[128];
  char value[256];
} PortMirroringConfig;
// Add at the top after includes
static int current_port = 0; // Global variable to track current port

// Add after current_port declaration
#define CONFIG_FILE_PORT "port_config.txt"
#define AUTO_MANUAL_CONFIG_FILE "/home/acs/DDoS_HUY/Setting/config_auto_manual.conf"
#define DB_PATH "./GUI_HUY/server/database/sysnetdef.db"

// Function prototypes
void SetHTTPSDefender(int serial_port);
void new_menu(int serial_port);
void port_mirroring_menu(int serial_port);
void SetABCDefenderMode(int serial_port);
void SetABCThresholdMode(int serial_port);

void send_reset(int serial_port);
void *key_listener(void *arg);
int configure_serial_port(const char *device, int baud_rate);
int send_data(int serial_port, const char *data, size_t size);
char *receive_data(int serial_port);
void ModeStart_cnt(int serial_port);
void ModeStart(int serial_port);
void options_mode1(int serial_port);
int kbhit(void);
void mode_select_login(int serial_port);
void reconfig(int serial_port);
void change_info_acc_admin_mode(int serial_port);
void display_logo1();
void display_logo2();
void ReturnMode2(int serial_port);
void ReturnMode2b(int serial_port);
void ReturnMode3();
void send_ipv4_address(int serial_port);
void send_ipv6_address(int serial_port);
void send_ipv4_address_http_add(int serial_port);
void send_ipv6_address_http_add(int serial_port);
void send_ipv4_address_http_remove(int serial_port);
void send_ipv6_address_http_remove(int serial_port);
int validate_ip_address(const char *ip_address);
void SaveEEPROM(int serial_port);
void printf_uart1(int serial_port);
void send_array(int serial_port);
void send_duration_time(int serial_port);
void printf_uart(int serial_port);
void send_user_time(int serial_port);
int validate_time_format(const char *time_string);
void input_and_send_account(int serial_port);
void input_and_send_account1(int serial_port);
void input_and_send_account2(int serial_port);
void check_account(int serial_port);
void check_username_change_pass(int serial_port);
void delete_account(int serial_port);
void add_acount(int serial_port);
void input_and_send_username(int serial_port);
void input_and_send_password(int serial_port);
void load_default(int serial_port);
//
void SetDateTime(int serial_port);
void SetDefenderPort(int serial_port);
void SetPortDefender(int serial_port);
void SetIPv4Target(int serial_port);
void Check_Table_IPv4();
void SetIPv6Target(int serial_port);
void SetIPv4Block(int serial_port);
void SetIPv6Block(int serial_port);
void RemoveIPv4Block(int serial_port);
void RemoveIPv6Block(int serial_port);
void SetSynDefender(int serial_port);
void SetSynonymousDefender(int serial_port);
void SetUDPDefender(int serial_port);
void SetDNSDefender(int serial_port);
void SetICMPDefender(int serial_port);
void SetIPSecDefender(int serial_port);
void SetTCPFragDefender(int serial_port);
void SetUDPFragDefender(int serial_port);
void SetHTTPDefender(int serial_port);
void SetHTTPDefender(int serial_port);
void set_HTTP_IP_Table(int serial_port);
void remove_ip_HTTP_from_hash(const char *ip);
void remove_ip_from_file(const char *filename, const char *ip);
void display_port_mirroring_config_from_db(int serial_port , int show_prompt);
//
void SetTimeflood(int serial_port);
void SetSynThresh(int serial_port);
void SetAckThresh(int serial_port);
void SetTimeDelete(int serial_port);
void SetUDPThresh(int serial_port);
void SetUDPThresh1s(int serial_port);
void SetDNSThresh(int serial_port);
void SetICMPThresh(int serial_port);
void SetICMPThresh1s(int serial_port);
void SetIPSecThresh(int serial_port);
void AddIPv4VPN(int serial_port);
void RemoveIPv4VPN(int serial_port);
void AddIPv6VPN(int serial_port);
void RemoveIPv6VPN(int serial_port);
void SetDurationTime(int serial_port);
void ConfigTypePacket(int serial_port, PortMirroringConfig *cfg);
void Select_traffic_mirroring_mode(int serial_port, PortMirroringConfig *cfg);
void Add_port_mirroring(int serial_port);
void save_port_mirroring_to_db(const PortMirroringConfig *cfg);
void InputDestMAC(char *mac);
void InputSourceMAC(char *mac);
void InputDestIP(char *ip);
void InputProtocol(int *protocol, char *protocol_str);
void InputDestMAC(char *mac);
void InputSourceIP(char *ip);
void InputSourceMAC(char *mac);
void InputDestPort(char *port);
void InputSourcePort(char *port);
void Delete_port_mirroring(int serial_port);
void Update_port_mirroring(int serial_port);
// void display_port_mirroring_config_api(int serial_port);
//
void DisplayAccount(int serial_port);
void reset_account(int serial_port);
void change_root(int serial_port);
void setload_default(int serial_port);
//
void user_mode(int serial_port);
void admin_mode(int serial_port);
void user_change_info(int serial_port);
void change_user_pass(int serial_port);
//
void Mode_Condition_SDCard(int serial_port);
void display_memory();
void display_log_files(const char *dir_path);
void create_new_log_file();
void delete_log_file(const char *dir_path);
void read_threshold_timecounter_from_file();
void write_threshold_time_counter_to_file();
void update_threshold_time_counter();
void read_threshold_from_file();
void write_threshold_to_file();
void update_threshold_SDCard();
void read_config_mode_save_logfile();
void write_config_mode_save_logfile();
void update_mode_auto_manual();
void display_setting_admin();
void display_setting_user();
void display_setting_user1();
void Mode_Condition_SDCard_User(int serial_port);
void Mode_Condition_SDCard_Admin(int serial_port);
//
void print_payload(const unsigned char *buffer, int size);
void process_packet(unsigned char *buffer, int size);
void update_lcd(const char *message);
void *lcd_thread_function(void *arg);
void scroll_text1(const char *text1, const char *text2, int delay_ms);
void scroll_text(const char *text, int delay_ms);
//
void get_current_date(char *date_str);
void get_custom_datetime(char *date_str);
void send_time(int serial_port);
// void remove_old_logs(void);
int open_and_check_dir(const char *dir_path);
void *memory_check_thread_function(void *arg);
void *run(void *arg);
void previous_mode_fc();
//
void *packet_queue_processing_thread(void *arg);
void enqueue_packet(unsigned char *packet, int size);
void *logging_thread_function(void *arg);
// void *log_buffer_thread(void *arg);
void check_connect_eth();
// void open_attacker_log_file();
// void close_attacker_log_file();
// void log_attacker_ip(const char *src_ip);
void load_ips_from_file(const char *filename);
void flush_batch_to_file(const char *filename);
void create_http_filelog(const char *filename);
//
void display_table(int serial_port);
void display_account(int serial_port);
void process_ip(const char *filename, const char *ip);
void send_http_ipv4_start(int serial_port, const char *filename);
void send_http_ipv6_start(int serial_port, const char *filename);
void send_data_sync_time(int serial_port);
void send_ips_via_uart(const char *filename);
void uart_send(const char *data, int serial_port);
//
#define LCD_ADDR 0x27
#define BUFFER_SIZE 512
#define TARGET_MAC {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA}
#define TARGET_MAC_ATTACK {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
#define LOG_FLOOD_DIR "Log/Log_Flood"
#define LOG_NORMAL_DIR "Log/Log_Normal"
#define ATTACKER_LOG_DIR "HTTP_ip_table"
#define LOGFILE_HTTP_IPv4 "HTTP_ip_table/http_ipv4.log"
#define LOGFILE_HTTP_IPv6 "HTTP_ip_table/http_ipv6.log"
#define MAX_LOG_DAYS 5
#define SAMPLING_RATE 1

#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define RESET "\x1B[0m" // Reset
//
#define MAX_IP_LEN 42
#define MAX_IPS 65536
#define BATCH_SIZE 1
#define BUFFER_SIZE_SEND_IP_VIA_UART 8192
//
int serial_port;
float Threshold_SD;
int Threshold_time_counter;
const char *previous_mode = "/home/acs/DDoS_HUY/Setting/mode.conf";
// const char *time_check_create_log = "/home/antiddos/DDoS_V1/Setting/time_check_create_log.txt";
const char *threshold_logfile = "/home/acs/DDoS_HUY/Setting/threshold_logfile.conf";
const char *time_counter = "/home/acs/DDoS_HUY/Setting/time_counter.conf";
#define CONFIG_FILE "/home/acs/DDoS_HUY/Setting/config_auto_manual.conf"
volatile bool auto_delete_logs;
volatile int stop_scrolling = 0;
bool reset_program = false;
char bw1[16];
static unsigned char prev_time[4] = {0}; // Luu th?i gian c?a g i tru?c d
static unsigned int bw_accumulated = 0;
char uds_msg[256];
char name_logfile[32];
//
I2C16x2 lcd;
unsigned char target_mac[6] = TARGET_MAC;
unsigned char target_mac_attack[6] = TARGET_MAC_ATTACK;
static char current_attack[255] = "";
time_t last_packet_time;
pthread_mutex_t log_mutex;          // Mutex for synchronizing log access
pthread_mutex_t lcd_mutex;          // Mutex for synchronizing LCD updates
pthread_mutex_t packet_queue_mutex; // Mutex for packet queue
pthread_cond_t packet_queue_cond;   // Condition variable for packet queue
pthread_t run_thread;
pthread_mutex_t run_mutex = PTHREAD_MUTEX_INITIALIZER; // run
// FILE *current_log_file = NULL;                         // Bien luu tru con tro logfile
// FILE *attacker_log_file = NULL;
FILE *current_log_file_flood = NULL;  // Bien luu tru con tro logfile
FILE *current_log_file_normal = NULL; // Bien luu tru con tro logfile
GHashTable *ip_table;
GQueue *batch_queue;
// LCD update queue

char key_enter = '\r';
char key_admin = '>';
char key_check_account = '/';
char key_show_info = '*';

#define QUEUE_SIZE 1024
typedef struct
{
  char messages[QUEUE_SIZE][255];
  int front;
  int rear;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} MessageQueue;
MessageQueue lcd_queue;

// struct MemoryStruct
// {
//   char *memory;
//   size_t size;
// };

// Packet queue
#define PACKET_QUEUE_SIZE 4096
typedef struct
{
  unsigned char packets[PACKET_QUEUE_SIZE][BUFFER_SIZE];
  int front;
  int rear;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} PacketQueue;
PacketQueue packet_queue;

// Buffer for logging
// #define LOG_BUFFER_SIZE (1024 * 42768)
// char log_buffer[LOG_BUFFER_SIZE];
// int log_buffer_pos = 0;

// Buffer printf terminal
#define PRINT_BUFFER_SIZE 1024
char print_buffer[PRINT_BUFFER_SIZE];
int print_buffer_pos = 0;
char name_logfile_flood[64];
char name_logfile_normal[64];
//
bool full_sd = false;
bool full_sd1;
// bool full_sd2 = false;
bool is_run_running = false;
bool is_connected = true;
bool show_disconnected_message = false;
bool is_idle = false;
bool is_idle2 = false;
bool stop_writing;
bool detect_attack = false;
bool empty_log_normal = false;
bool close_normal_log = false;
bool close_flood_log = false;
//
int count_tancong = 0;
int count_tong = 0;
int count_bth = 0;

void display_table(int serial_port)
{
  sleep(1);
  char key_table = '<';
  write(serial_port, &key_table, sizeof(key_table));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);
  printf_uart(serial_port);
}

void display_account(int serial_port)
{
  char key = '>';
  write(serial_port, &key, sizeof(key));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);
  printf_uart(serial_port);
}

//
void change_user_pass(int serial_port)
{
  char key_mode = '|';
  char enter[] = {'\r'};
  char password[17];
  int valid_input = 0;
  while (!valid_input)
  {
    printf("\r\n\t\t| New Password: ");
    scanf("%16s", password);
    if (strlen(password) > 16)
    {
      printf("The account or password exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }

  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_password = strlen(password);
  for (int i = 0; i < n_password; i++)
  {
    usleep(50000);
    char data[2] = {password[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void user_change_info(int serial_port)
{
  // char key_mode = '|';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  change_user_pass(serial_port);
}

void user_mode(int serial_port)
{
start:
  char key = 0;
  char enter = '\r';
  display_table(serial_port);
  usleep(100000);
  printf("\r\n\t\t+===========+============================================================================= Session-User =====================================================================================+");
  printf("\r\n\t\t| DISPLAY   |                                                                                                                                                                                |");
  printf("\r\n\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     1.    | Re-configure Anti-DDoS                                                                                                                                                         |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     2.    | Change password                                                                                                                                                                |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     3.    | View log file status and change time counter                                                                                                                                   |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     4.    | Exit                                                                                                                                                                           |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n   SETTING     --> Please choose Mode: ");

  while (1)
  {
    scanf("%c", &key);

    if (key == '1' || key == '2' || key == '4' || key == '3')
    {
      break;
    }
    if (key != '1' || key != '2' || key != '3' || key != '4')
    {
      printf("\r     SETTING    | --> Please choose Mode: ");
    }
  }

  if (key == '1')
  {
    sleep(1);
    reconfig(serial_port);
    system("clear");
    goto start;
  }
  else if (key == '2')
  {
    sleep(1);
    user_change_info(serial_port);
    system("clear");
    goto start;
  }
  else if (key == '3')
  {
    //   sleep(1);
    Mode_Condition_SDCard_User(serial_port);
    goto start;
  }
  else if (key == '4')
  {
  }
}

void admin_mode(int serial_port)
{
start:
  char key = 0;
  char enter = '\r';
  display_table(serial_port);
  usleep(100000);
  printf("\r\n\t\t+===========+============================================================================= Session-Admin ====================================================================================+");
  printf("\r\n\t\t| DISPLAY   |                                                                                                                                                                                |");
  printf("\r\n\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     1.    | Re-configure Anti-DDoS                                                                                                                                                         |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     2.    | Change account information                                                                                                                                                     |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     3.    | Setting SD card and change time counter                                                                                                                                        |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t|     4.    | Exit                                                                                                                                                                           |");
  printf("\r\n\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n   SETTING    | --> Please choose Mode: ");

  while (1)
  {
    scanf("%c", &key);
    if (key == '1' || key == '2' || key == '4' || key == '3')
    {
      break;
    }
    if (key != '1' || key != '2' || key != '3' || key != '4')
    {
      printf("\r     SETTING    | --> Please choose Mode: ");
    }
  }

  if (key == '1')
  {
    sleep(1);
    // reconfig(serial_port);
    system("clear");
    goto start;
  }
  else if (key == '2')
  {
    sleep(1);
    change_info_acc_admin_mode(serial_port);
    system("clear");
    goto start;
  }
  else if (key == '3')
  {
    // sleep(1);
    Mode_Condition_SDCard_Admin(serial_port);
    goto start;
  }
  else if (key == '4')
  {
    // system("clear");
    // ModeStart(serial_port);
  }
}

// void display_logo1()
// {
//   printf("\r\n *************************************************************************************************************************************************************************************************************");
//   printf("\r\n **                                                                                                                                                                                                         **");
//   printf("\r\n **                                                                        ____  ____       ____        ____        __                _                                                                     **");
//   printf("\r\n **                                                                       |  _ '|  _ '  ___/ ___|      |  _ '  ___ / _| ___ _ __   __| | ___ _ __                                                           **");
//   printf("\r\n **                                                                       | | | | | | |/ _ '___ '  ___ | | | |/ _ ' |_ / _ ' '_ ' / _` |/ _ ' '__|                                                          **");
//   printf("\r\n **                                                                       | |_| | |_| | (_) |_ ) )|___|| |_| | |/_/  _|  __/ | | | (_| |  __/ |                                                             **");
//   printf("\r\n **                                                                       |____/|____/ '___/____/      |____/ '___|_|  '___|_| |_|'__,_|'___|_|                                                             **");
//   printf("\r\n **                                                                                                                                                                                                         **");
//   printf("\r\n *************************************************************************************************************************************************************************************************************");
//   printf("\r\n                                                                                                                                                                ***** DDoS Defender by Acronics Solutions ****");
// }

void display_logo1()
{
  printf("\r\n *************************************************************************************************************************************************************************************************************");
  printf("\r\n **                                                                                                                                                                                                         **");
  printf("\r\n **                                                                   _    ____ ____    ____                       _             ____        __                                                             **");
  printf("\r\n **                                                                  / \\  / ___/ ___|  / ___| _   _ ___ _ __   ___| |_          |  _ \\  ___ / _|                                                            **");
  printf("\r\n **                                                                 / _ \\| |   \\___ \\  \\___ \\| | | / __| '_ \\ / _ \\ __|  _____  | | | |/ _ \\ |_                                                             **");
  printf("\r\n **                                                                / ___ \\ |___ ___) |  ___) | |_| \\__ \\ | | |  __/ |_  |_____| | |_| |  __/  _|                                                            **");
  printf("\r\n **                                                               /_/   \\_\\____|____/  |____/ \\__, |___/_| |_|\\___|\\__|         |____/ \\___|_|                                                              **");
  printf("\r\n **                                                                                           |___/                                                                                                         **");
  printf("\r\n **                                                                                                                                                                                                         **");
  printf("\r\n *************************************************************************************************************************************************************************************************************");
  printf("\r\n                                                                                                                                                                ***** DDoS Defender by Acronics Solutions ****");
}

void ModeStart_cnt(int serial_port)
{
  char key1;
  char key2 = '1';
  bool check = false;
  char key;
  char enter = '\r';
  for (int i = Threshold_time_counter; i >= 0; i--)
  {
    system("clear");
    display_logo1();
    printf("\r\n                                                                                                                                                                                                             |");
    printf("\r\n ================+===========+===============================================================================================================================================================================+");
    printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
    printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
    printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    printf("\r\n\t\t |     1:    | Show flow information or display it automatically after %d  s                                                                                                                 |", i);
    printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    printf("\r\n\t\t |     2:    | View current configurations                                                                                                                                                   |");
    printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    printf("\r\n\t\t |     3:    | Config Setting                                                                                                                                                                |");
    printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    printf("\r\n ================+===========================================================================================================================================================================================+\n");
    printf("\r    SETTING     | --> Please choose Mode: ");
    sleep(1);

    if (kbhit())
    {
      key = getchar();
      if (key == '1' || key == '2' || key == '3')
      {
        break;
      }
    }
    key = '1';
  }
  // if (detect_attack)
  // {
  //   printf("\033[10B"); // Xuá»‘ng 10 dÃ²ng
  //   printf("\033[10D"); // Qua trÃ¡i 10 cá»™t
  //   printf("\033[1;36m \n The attack has been detected!!!\033[0m");
  //   printf("\033[1;36m \n Return to the monitoring page? \033[0m");
  //   while (1)
  //   {
  //     scanf("%c", &key1);

  //     if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
  //     {
  //       break;
  //     }
  //     if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
  //     {
  //       printf("\r    --> Please choose : ");
  //     }
  //   }

  //   if (key == 'y' || key == 'Y')
  //   {
  //     printf_uart1(serial_port);
  //   }
  // }
  if (key == '2')
  {
    system("clear");
    display_logo1();
    mode_select_login(serial_port);
    ModeStart(serial_port);
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    // write(serial_port, &key_check_account, sizeof(key_check_account));
    // usleep(100000);
    // write(serial_port, &key_enter, sizeof(key_enter));
    // usleep(100000);
    check_account(serial_port);
    ModeStart(serial_port);
  }
  else if (key == '1')
  {
    system("clear");
    // display_logo1();
    printf_uart1(serial_port);
    ModeStart(serial_port);
  }
}

void ModeStart(int serial_port)
{
start:
  system("clear");
  display_logo1();
  char key;
  char enter = '\r';
  printf("\r\n                                                                                                                                                                                                             |");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
  printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     1:    | Show flow information                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     2:    | View current configurations                                                                                                                                                   |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     3:    | Config Setting                                                                                                                                                                |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========================================================================================================================================================================================+\n");

  while (1)
  {
    scanf("%c", &key);
    if (key == '1' || key == '2' || key == '3')
    {
      break;
    }
    if (key != '1' || key != '2' || key != '3')
    {
      printf("\r     SETTING     | --> Please choose Mode: ");
    }
  }

  if (key == '2')
  {
    system("clear");
    display_logo1();
    mode_select_login(serial_port);
    goto start;
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    // write(serial_port, &key_check_account, sizeof(key_check_account));
    // usleep(100000);
    // write(serial_port, &key_enter, sizeof(key_enter));
    // usleep(100000);
    check_account(serial_port);
    goto start;
  }
  else if (key == '1')
  {
    system("clear");
    // display_logo1();
    printf_uart1(serial_port);
    goto start;
  }
}

void options_mode1(int serial_port)
{
  // system("clear");
  display_logo1();
start:
  char key;
  char enter = '\r';
  printf("\r\n                                                                                                                                                                                                             |");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     1:    | Return mode start                                                                                                                                                             |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     2:    | Continue to show flow information                                                                                                                                             |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     3:    | Show current configuration                                                                                                                                                    |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     4:    | Monitor SD card status                                                                                                                                                        |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ----------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========================================================================================================================================================================================+\n");
  printf("\r\n     SETTING     | --> Please choose Mode: ");

  while (1)
  {
    scanf("%c", &key);
    if (key == '4')
    {
      system("clear");
      display_logo1();
      Mode_Condition_SDCard(serial_port);
      break;
    }
    else if (key == '1' || key == '2' || key == '3')
    {
      break;
    }
    if (key != '1' || key != '2' || key != '3' || key != '4')
    {
      printf("\r     SETTING     | --> Please choose Mode: ");
    }
  }

  if (key == '1')
  {
    ModeStart(serial_port);
  }
  else if (key == '2')
  {
    system("clear");
    // display_logo1();
    printf_uart1(serial_port);
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    mode_select_login(serial_port);
    goto start;
  }
}
void mode_select_login(int serial_port)
{
  display_table(serial_port);
  // sleep(1);
  char key;
  char enter = '\r';
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\nSetting     | Do you want login to configure? (Y/N) ?: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      break;
    }
    else if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\rSetting     | Do you want login to configure? (Y/N) ?: ");
    }
  }

  if (key == 'y' || key == 'Y')
  {
    system("clear");
    display_logo1();
    // write(serial_port, &key_check_account, sizeof(key_check_account));
    // usleep(100000);
    // write(serial_port, &key_enter, sizeof(key_enter));
    // usleep(100000);
    check_account(serial_port);
    sleep(1.5);
  }
  else if (key == 'n' || key == 'N')
  {
    system("clear");
    display_logo1();
  }
}

void check_account(int serial_port)
{
start:
  input_and_send_account(serial_port);
  char *data = receive_data(serial_port);
  if (data == NULL)
  {
    printf("Error receiving data\n");
    return;
  }

  if ((strchr(data, 'F') != NULL) || (strchr(data, 'f') != NULL))
  {
    printf("\r\n\t\t=============================================================================================================================================================================================+");
    printf("\r\n\t\t| Warning: Incorrect password/username. Retry!                                                                           ");
    usleep(10000);
    goto start;
  }
  else if ((strchr(data, 'Y') != NULL) || (strchr(data, 'y') != NULL))
  {
    printf("\r\n\t\t=============================================================================================================================================================================================+");
    printf("\r\n\t\t| Wrong password 3 times.                                                                                                |");
    printf("\r\n\t\t|                                                                                                                        |");
    printf("\r\n\t\t+------------------------------------------------------------------------------------------------------------------------+");
    usleep(500000);
    // system("clear");
  }
  else if ((strchr(data, 'U') != NULL))
  {
    printf("\r\n\t\t=============================================================================================================================================================================================+");
    printf("\r\n\t\t| User login successfully !!!                         ");
    printf("\r\n----------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    sleep(1);
    system("clear");
    display_logo1();
    user_mode(serial_port);
  }
  else if ((strchr(data, 'A') != NULL))
  {
    printf("\r\n\t\t=============================================================================================================================================================================================+");
    printf("\r\n\t\t| Admin login successfully !!!                                                                                           ");
    printf("\r\n----------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    sleep(1);
    system("clear");
    display_logo1();
    admin_mode(serial_port);
  }
}
void check_username_change_pass(int serial_port)
{
  // char key_mode = '(';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  input_and_send_account2(serial_port);

  char *data = receive_data(serial_port);

  if (data == NULL)
  {
    printf("Error receiving data\n");
    return;
  }
  else if ((strchr(data, 'Y') != NULL))
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    printf("\r\n\t\t\t\t\t\t Change Successfully !!!                                                                                            ");
  }
  else if ((strchr(data, 'X') != NULL))
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    printf("\r\n\t\t\t\t\t\t Change Error !!!                                                                                            ");
  }
  ReturnMode3();
}

// void reconfig(int serial_port)
// {
// start:
//   display_logo1();
//   char key = 0;
//   char enter = '\r';
//   printf("\r\n *************************************************************************************************************************************************************************************************************");
//   printf("\r\n");
//   printf("\r\n ============================================================================================================================================================================================================+");
//   printf("\r\n ==> Mode 2 is selected                                                                                                                                                                                      |");
//   printf("\r\n");
//   printf(" ===============+===========+================================================================================================================================================================================+\r\n");
//   printf("    DISPLAY     |           |                                                                                                                                                                                |\r\n");
//   printf("\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     1.    | Setting RTC.                                                                                                                                                                   |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     2.    | Setting Anti by Port mode(*).                                                                                                                                                  |\r\n");
//   printf("\t\t|           | 	->(Info: When Port protection mode(*) is enabled, IP protected mode (**) is disabled and vice versa).                                                                        |\r\n");
//   printf("\t\t|     3.    | Setting interface Port is protect.                                                                                                                                             |\r\n");
//   printf("\t\t|           | 	->(Info: Protected default Port interface is 1).                                                                                                                             |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     4.    | Setting IPv4 Server to protect(**).                                                                                                                                            |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     R.    | Setting IPv6 Server to protect(**).                                                                                                                                            |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     5.    | Setting attack detection time.                                                                                                                                                 |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1 second).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     6.    | Setting Anti-SYN flood.                                                                                                                                                        |\r\n");
//   printf("\t\t|     7.    | Setting SYN flood attack detection threshold.                                                                                                                                  |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     8.    | Setting ACK flood attack detection threshold.                                                                                                                                  |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     9.    | Setting the time to automatically delete the connection session information in the white list.                                                                                 |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 30 second).                                                                                                                                   |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     A.    | Setting Anti-LAND Attack.                                                                                                                                                      |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     B.    | Setting Anti-UDP flood.                                                                                                                                                        |\r\n");
//   printf("\t\t|     C.    | Setting UDP flood attack detection threshold.                                                                                                                                  |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t|     D.    | Setting threshold of valid UDP packer per second allowed.                                                                                                                      |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     E.    | Setting Anti-DNS Amplification attack.                                                                                                                                         |\r\n");
//   printf("\t\t|     F.    | Setting DNS Amplification attack detection threshold.                                                                                                                          |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     G.    | Setting Anti-ICMP flood.                                                                                                                                                       |\r\n");
//   printf("\t\t|     H.    | Setting ICMP flood attack detection threshold.                                                                                                                                 |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t|     I.    | Setting threshold of valid ICMP packer per second allowed.                                                                                                                     |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     J.    | Setting Anti-IPSec IKE flood.                                                                                                                                                  |\r\n");
//   printf("\t\t|     K.    | Setting IPSEC IKE flood attack detection threshold.                                                                                                                            |\r\n");
//   printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     L.    | Add VPN server name or address to legitimate VPN list.                                                                                                                         |\r\n");
//   printf("\t\t|     M.    | Remove the VPN server name or address from the legal VPN list.                                                                                                                 |\r\n");
//   printf("\t\t|     S.    | Add VPN server name or address IPv6 to legitimate VPN list.                                                                                                                    |\r\n");
//   printf("\t\t|     T.    | Remove the VPN server name or address IPv6 from the legal VPN list.                                                                                                            |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     N.    | Setting Anti-TCP fragmentation flood.                                                                                                                                          |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     O.    | Setting Anti-UDP fragmentation flood.                                                                                                                                          |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     P.    | Setting HTTP GET flood.                                                                                                                                                        |\r\n");
//   printf("\t\t|     Q.    | Setting Attacker's IP Table.                                                                                                                                                   |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     X.    | Setting HTTPS GET flood.                                                                                                                                                        |\r\n");
//   printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("\t\t|     Z.    | => Exit.                                                                                                                                                                       |\r\n");
//   printf("----------------+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
//   printf("    SETTING    | --> Your choice: ");

//   while (1)
//   {
//     scanf("%c", &key);
//     if (key == '1' || key == '2' || key == '3' || key == '4' || key == '5' || key == '6' || key == '7' || key == '8' || key == '9' || key == 'A' || key == 'a' || key == 'B' || key == 'b' || key == 'C' || key == 'c' || key == 'D' || key == 'd' || key == 'E' || key == 'e' || key == 'F' || key == 'f' || key == 'G' || key == 'g' || key == 'H' || key == 'h' || key == 'I' || key == 'i' || key == 'J' || key == 'j' || key == 'K' || key == 'k' || key == 'L' || key == 'l' || key == 'M' || key == 'm' || key == 'N' || key == 'n' || key == 'O' || key == 'o' || key == 'Z' || key == 'z' || key == 'P' || key == 'p' || key == 'Q' || key == 'q' || key == 'r' || key == 'R' || key == 's' || key == 'S' || key == 't' || key == 'T' || key == 'X')
//     {
//       break;
//     }
//     if (key != '1' || key != '2' || key != '3' || key != '4' || key != '5' || key != '6' || key != '7' || key != '8' || key != '9' || key != 'A' || key != 'a' || key != 'B' || key != 'b' || key != 'C' || key != 'c' || key != 'D' || key != 'd' || key != 'E' || key == 'e' || key == 'F' || key == 'f' || key == 'G' || key == 'g' || key == 'H' || key == 'h' || key == 'I' || key == 'i' || key != 'J' || key != 'j' || key != 'K' || key != 'k' || key != 'L' || key != 'l' || key != 'M' || key != 'm' || key != 'N' || key != 'n' || key != 'O' || key != 'o' || key != 'P' || key != 'p' || key != 'Q' || key != 'q' || key != 'Z' || key != 'z' || key != 'r' || key != 'R' || key != 'S' || key != 's' || key != 't' || key != 'T' || key == 'X')
//     {
//       printf("\r     SETTING    | --> Your choice: ");
//     }
//   }

//   usleep(500000);
//   if (key == '1')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetDateTime(serial_port);
//     goto start;
//   }
//   else if (key == '2')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetDefenderPort(serial_port);
//     goto start;
//   }
//   else if (key == '3')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetPortDefender(serial_port);
//     goto start;
//   }
//   else if (key == '4')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetIPv4Target(serial_port);
//     goto start;
//   }
//   else if (key == 'r' || key == 'R')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetIPv6Target(serial_port);
//     goto start;
//   }
//   else if (key == '5')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetTimeflood(serial_port);
//     goto start;
//   }
//   else if (key == '6')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetSynDefender(serial_port);
//     goto start;
//   }
//   else if (key == '7')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetSynThresh(serial_port);
//     goto start;
//   }
//   else if (key == '8')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetAckThresh(serial_port);
//     goto start;
//   }
//   else if (key == '9')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetTimeDelete(serial_port);
//     goto start;
//   }
//   else if (key == 'A' || key == 'a')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetSynonymousDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'B' || key == 'b')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetUDPDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'C' || key == 'c')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetUDPThresh(serial_port);
//     goto start;
//   }
//   else if (key == 'd' || key == 'D')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetUDPThresh1s(serial_port);
//     goto start;
//   }
//   else if (key == 'e' || key == 'E')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetDNSDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'F' || key == 'f')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetDNSThresh(serial_port);
//     goto start;
//   }
//   else if (key == 'G' || key == 'g')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetICMPDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'H' || key == 'h')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetICMPThresh(serial_port);
//     goto start;
//   }
//   else if (key == 'I' || key == 'i')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetICMPThresh1s(serial_port);
//     goto start;
//   }
//   else if (key == 'J' || key == 'j')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetIPSecDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'K' || key == 'k')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetIPSecThresh(serial_port);
//     goto start;
//   }
//   else if (key == 'L' || key == 'l')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     AddIPv4VPN(serial_port);
//     goto start;
//   }
//   else if (key == 'M' || key == 'm')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     RemoveIPv4VPN(serial_port);
//     goto start;
//   }
//   else if (key == 'S' || key == 's')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     AddIPv6VPN(serial_port);
//     goto start;
//   }
//   else if (key == 'T' || key == 't')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     RemoveIPv6VPN(serial_port);
//     goto start;
//   }
//   else if (key == 'N' || key == 'n')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetTCPFragDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'O' || key == 'o')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetUDPFragDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'P' || key == 'p')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetHTTPDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'Q' || key == 'q')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     set_HTTP_IP_Table(serial_port);
//     goto start;
//   }
//   else if (key == 'x' || key == 'X')
//   {
//     system("clear");
//     display_logo1();
//     display_table(serial_port);
//     SetHTTPSDefender(serial_port);
//     goto start;
//   }
//   else if (key == 'Z' || key == 'z')
//   {
//     system("clear");
//     display_logo1();
//     new_menu(serial_port);
//   }
// }
void reconfig(int serial_port)
{
start:
  //display_logo1();
  char key = 0;
  char enter = '\r';
  printf("\r\n *************************************************************************************************************************************************************************************************************");
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n ==> Mode 2 is selected                                                                                                                                                                                      |");
  printf("\r\n");
  printf(" ===============+===========+================================================================================================================================================================================+\r\n");
  printf("    DISPLAY     |           |                                                                                                                                                                                |\r\n");
  printf("\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     1.    | Setting Anti by Port mode(*).                                                                                                                                                  |\r\n");
  printf("\t\t|           | 	->(Info: When Port protection mode(*) is enabled, IP protected mode (**) is disabled and vice versa).                                                                        |\r\n");
  printf("\t\t|     2.    | Setting interface Port is protect.                                                                                                                                             |\r\n");
  printf("\t\t|           | 	->(Info: Protected default Port interface is 1).                                                                                                                             |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | Setting IPv4 Server to protect(**).                                                                                                                                            |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Setting IPv6 Server to protect(**).                                                                                                                                            |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     5.    | Setting Anti-SYN flood.                                                                                                                                                        |\r\n");
  printf("\t\t|     6.    | Setting SYN flood attack detection threshold.                                                                                                                                  |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     7.    | Setting ACK flood attack detection threshold.                                                                                                                                  |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     8.    | Setting the time to automatically delete the connection session information in the white list.                                                                                 |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 30 second).                                                                                                                                   |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     9.    | Setting Anti-LAND Attack.                                                                                                                                                      |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     A.    | Setting Anti-UDP flood.                                                                                                                                                        |\r\n");
  printf("\t\t|     B.    | Setting UDP flood attack detection threshold.                                                                                                                                  |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t|     C.    | Setting threshold of valid UDP packer per second allowed.                                                                                                                      |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     D.    | Setting Anti-DNS Amplification attack.                                                                                                                                         |\r\n");
  printf("\t\t|     E.    | Setting DNS Amplification attack detection threshold.                                                                                                                          |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     F.    | Setting Anti-ICMP flood.                                                                                                                                                       |\r\n");
  printf("\t\t|     G.    | Setting ICMP flood attack detection threshold.                                                                                                                                 |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t|     H.    | Setting threshold of valid ICMP packer per second allowed.                                                                                                                     |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     I.    | Setting Anti-IPSec IKE flood.                                                                                                                                                  |\r\n");
  printf("\t\t|     J.    | Setting IPSEC IKE flood attack detection threshold.                                                                                                                            |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1000 PPS).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  /* Removed options L and M: VPN IPv4 list.
  printf("\t\t|     L.    | Add VPN server name or address to legitimate VPN list.                                                                                                                         |\r\n");
  printf("\t\t|     M.    | Remove the VPN server name or address from the legal VPN list.                                                                                                                 |\r\n");
  */
  /* Removed options S and T: VPN IPv6 list.
  printf("\t\t|     S.    | Add VPN server name or address IPv6 to legitimate VPN list.                                                                                                                    |\r\n");
  printf("\t\t|     T.    | Remove the VPN server name or address IPv6 from the legal VPN list.                                                                                                            |\r\n");
  */
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     K.    | Setting Anti-TCP fragmentation flood.                                                                                                                                          |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     L.    | Setting Anti-UDP fragmentation flood.                                                                                                                                          |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     M.    | Setting HTTP GET flood.                                                                                                                                                        |\r\n");
  printf("\t\t|     N.    | Setting Attacker's IP Table.                                                                                                                                                   |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     O.    | Setting HTTPS GET flood.                                                                                                                                                        |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     Z.    | => Exit.                                                                                                                                                                       |\r\n");
  printf("----------------+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("    SETTING    | --> Your choice: ");

  // Updated valid keys (removed '1', '5', 'L', 'M', 'S', 'T')
  while (1)
  {
    scanf("%c", &key);
    if (key == '2' || key == '3' || key == '4' ||
        key == '6' || key == '7' || key == '8' || key == '9' ||
        key == 'A' || key == 'a' || key == 'B' || key == 'b' ||
        key == 'C' || key == 'c' || key == 'D' || key == 'd' ||
        key == 'E' || key == 'e' || key == 'F' || key == 'f' ||
        key == 'G' || key == 'g' || key == 'H' || key == 'h' ||
        key == 'I' || key == 'i' || key == 'J' || key == 'j' ||
        key == 'K' || key == 'k' || key == 'N' || key == 'n' ||
        key == 'O' || key == 'o' || key == 'Z' || key == 'z' ||
        key == 'P' || key == 'p' || key == 'Q' || key == 'q' ||
        key == 'r' || key == 'R' || key == 'X' || key == 'x' || key == 'W' || key == 'w' ||
        key == 'Y' || key == 'y')
    {
      break;
    }
    // Also update the invalid key check accordingly.
    if (key != '2' && key != '3' && key != '4' &&
        key != '6' && key != '7' && key != '8' && key != '9' &&
        key != 'A' && key != 'a' && key != 'B' && key != 'b' &&
        key != 'C' && key != 'c' && key != 'D' && key != 'd' &&
        key != 'E' && key != 'e' && key != 'F' && key != 'f' &&
        key != 'G' && key != 'g' && key != 'H' && key != 'h' &&
        key != 'I' && key != 'i' && key != 'J' && key != 'j' &&
        key != 'K' && key != 'k' && key != 'N' && key != 'n' &&
        key != 'O' && key != 'o' && key != 'Z' && key != 'z' &&
        key != 'P' && key != 'p' && key != 'Q' && key != 'q' &&
        key != 'r' && key != 'R' && key != 'X' && key != 'x' && key != 'W' && key != 'w' && key != 'Y' && key != 'y')
    {
      printf("\r     SETTING    | --> Your choice: ");
    }
  }

  usleep(500000);
  /* Removed branch for key '1'
  if (key == '1')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetDateTime(serial_port);
    goto start;
  }
  */
  if (key == '2')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetDefenderPort(serial_port);
    goto start;
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetPortDefender(serial_port);
    goto start;
  }
  else if (key == '4')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetIPv4Target(serial_port);
    goto start;
  }

  else if (key == 'r' || key == 'R')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetIPv6Target(serial_port);
    goto start;
  }
  /* Removed branch for key '5'
  else if (key == '5')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetTimeflood(serial_port);
    goto start;
  }
  */
  else if (key == '6')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetSynDefender(serial_port);
    goto start;
  }
  else if (key == '7')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetSynThresh(serial_port);
    goto start;
  }
  else if (key == '8')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetAckThresh(serial_port);
    goto start;
  }
  else if (key == '9')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetTimeDelete(serial_port);
    goto start;
  }
  else if (key == 'A' || key == 'a')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetSynonymousDefender(serial_port);
    goto start;
  }
  else if (key == 'B' || key == 'b')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetUDPDefender(serial_port);
    goto start;
  }
  else if (key == 'C' || key == 'c')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetUDPThresh(serial_port);
    goto start;
  }
  else if (key == 'd' || key == 'D')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetUDPThresh1s(serial_port);
    goto start;
  }
  else if (key == 'e' || key == 'E')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetDNSDefender(serial_port);
    goto start;
  }
  else if (key == 'F' || key == 'f')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetDNSThresh(serial_port);
    goto start;
  }
  else if (key == 'G' || key == 'g')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetICMPDefender(serial_port);
    goto start;
  }
  else if (key == 'H' || key == 'h')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetICMPThresh(serial_port);
    goto start;
  }
  else if (key == 'I' || key == 'i')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetICMPThresh1s(serial_port);
    goto start;
  }
  else if (key == 'J' || key == 'j')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetIPSecDefender(serial_port);
    goto start;
  }
  else if (key == 'K' || key == 'k')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetIPSecThresh(serial_port);
    goto start;
  }
  /* Removed branches for keys 'L'/'l', 'M'/'m', 'S'/'s', 'T'/'t'
  else if (key == 'L' || key == 'l')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    AddIPv4VPN(serial_port);
    goto start;
  }
  else if (key == 'M' || key == 'm')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    RemoveIPv4VPN(serial_port);
    goto start;
  }
  else if (key == 'S' || key == 's')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    AddIPv6VPN(serial_port);
    goto start;
  }
  else if (key == 'T' || key == 't')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    RemoveIPv6VPN(serial_port);
    goto start;
  }
  */
  else if (key == 'N' || key == 'n')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetTCPFragDefender(serial_port);
    goto start;
  }
  else if (key == 'O' || key == 'o')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetUDPFragDefender(serial_port);
    goto start;
  }
  else if (key == 'P' || key == 'p')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetHTTPDefender(serial_port);
    goto start;
  }
  else if (key == 'Q' || key == 'q')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    set_HTTP_IP_Table(serial_port);
    goto start;
  }
  else if (key == 'x' || key == 'X')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetHTTPSDefender(serial_port);
    goto start;
  }
  else if (key == 'Z' || key == 'z')
  {
    system("clear");
    display_logo1();
    new_menu(serial_port);
  }
  else if (key == 'W' || key == 'w')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetABCDefenderMode(serial_port);
    goto start;
  }
  else if (key == 'Y' || key == 'y')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetABCThresholdMode(serial_port);
    goto start;
  }
}

void SetDateTime(int serial_port)
{
  char key_mode = '1';
  display_table(serial_port);
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);
  printf("\r\n\t\t");
  printf("\r\n\t\t");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n   Time - Date  |               Setting Time-Date for System Anti-DDoS                                                                                                                                       |");
  printf("\r\n\t\t+============================================================================================================================================================================================+");
  printf("\r\n\t\t| Enter the time in the format (YYYY-MM-DD HH:MM:SS) ");
  send_user_time(serial_port);
  ReturnMode2(serial_port);
}
void SaveEEPROM(int serial_port)
{

  char key;
  char enter = '\r';
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n SETTING     | Do you want to finish configuring now (Y/N)?: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r   SETTING     | Do you want to finish configuring now (Y/N)?: ");
    }
  }
  char *data = receive_data(serial_port);
  if (data == NULL)
  {
    printf("Error receiving data\n");
    return;
  }
  // ////printf("Received message: %s\n", data);
  if ((strchr(data, 'y') != NULL) || (strchr(data, 'Y') != NULL))
  {
    printf_uart1(serial_port);
  }
  else if ((strchr(data, 'n') != NULL) || (strchr(data, 'N') != NULL))
  {
    ModeStart(serial_port);
  }
}

void SetDefenderPort(int serial_port)
{
  char key_mode = '2';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);

  char key;
  char enter = '\r';
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable protect by interface port %d now (Y/N)? ", current_port);
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable protect by interface port now (Y/N)?: ");
    }
  }

  if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
  {
    ReturnMode2(serial_port);
  }
}
void SetPortDefender(int serial_port)
{
  char key_mode = '3';
  char key;
  char key1 = '1';
  char key0 = '0';
  char enter = '\r';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r   SETTING   | Enter port number for client side (Internet side) for Port %d (1/2):  ", current_port);
  while (1)
  {
    scanf("%c", &key);
    if (key == '1')
    {
      write(serial_port, &key0, sizeof(key0));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    else if (key == '2')
    {
      write(serial_port, &key1, sizeof(key1));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != '1' || key != '2')
    {
      printf("\r   SETTING   | Enter port number for client side (Internet side) for Port %d (1/2):  ", current_port);
    }
  }

  if (key == '1' || key == '2')
  {
    ReturnMode2(serial_port);
  }
}
void SetTimeflood(int serial_port)
{
  char key_mode = '5';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter attack detection time (s): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

void SetSynDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = '6';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable SYN flood protect now (Y/N)?:  ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable SYN flood protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void SetSynThresh(int serial_port)
{
  char key_mode = '7';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming SYN packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

//////////////////////////////////////////////////////////////////////
void SetABCDefenderMode(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'W';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable ABC flood protect now (Y/N)?:  ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable ABC flood protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void SetABCThresholdMode(int serial_port)
{
  char key_mode = 'Y';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming ABC packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}
//////////////////////////////////////////////////////////////////////////////////////////////////

void SetAckThresh(int serial_port)
{
  char key_mode = '8';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming ACK packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

void SetDurationTime(int serial_port)
{
  // char key_mode = '%';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of duration time export");
  send_duration_time(serial_port);
  ReturnMode2(serial_port);
}
void SetTimeDelete(int serial_port)
{
  char key_mode = '9';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the time to delete the whitelist's information (s): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}
void SetSynonymousDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'A';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable LAND Attack protect now (Y/N)?:   ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable LAND Attack protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void SetUDPDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'b';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable UDP flood protect now (Y/N)?:   ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable UDP flood protect now (Y/N)?:  ");
    }
  }
  ReturnMode2(serial_port);
}

void SetUDPThresh(int serial_port)
{
  char key_mode = 'c';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming UDP packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}
void SetUDPThresh1s(int serial_port)
{
  char key_mode = 'd';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the limit of incoming UDP packet per second (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}
void SetDNSDefender(int serial_port)
{
  char key_mode = 'e';
  char key;
  char enter = '\r';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n       SETTING    | Do you want to enable DNS flood protect now (Y/N)?:  ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r     SETTING    | Do you want to enable DNS flood protect now (Y/N)?: ");
    }
  }
  ReturnMode2(serial_port);
}

void SetDNSThresh(int serial_port)
{
  char key_mode = 'f';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming DNS request threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

void SetICMPDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'g';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable ICMP Attack protect now (Y/N)?:   ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable ICMP Attack protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void SetICMPThresh(int serial_port)
{
  char key_mode = 'h';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the value of incoming ICMP request packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}
void SetICMPThresh1s(int serial_port)
{
  char key_mode = 'i';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter the limit of incoming ICMP packet per second (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

void SetIPSecDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'j';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING       | Do you want to enable IPSec Attack protect now (Y/N)?:   ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       | Do you want to enable IPSec Attack protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void SetIPSecThresh(int serial_port)
{
  char key_mode = 'k';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\n    SETTING     | Enter the value of incoming IPSec IKE packet threshold (PPS): ");
  send_array(serial_port);
  ReturnMode2(serial_port);
}

void AddIPv4VPN(int serial_port)
{
  char key_mode = 'l';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter Server IPv4 VPN address want to add: ");
  send_ipv4_address(serial_port);
  ReturnMode2b(serial_port);
}
void RemoveIPv4VPN(int serial_port)
{
  char key_mode = 'm';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter Server IPv4 address want to remove: ");
  send_ipv4_address(serial_port);
  ReturnMode2b(serial_port);
}

void AddIPv6VPN(int serial_port)
{
  char key_mode = '#';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter Server IPv6 VPN address want to add: ");
  send_ipv6_address(serial_port);
  ReturnMode2b(serial_port);
}
void RemoveIPv6VPN(int serial_port)
{
  char key_mode = '^';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Enter Server IPv6 address want to remove: ");
  send_ipv6_address(serial_port);
  ReturnMode2b(serial_port);
}

void SetTCPFragDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'n';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n     SETTING      | Do you want to enable TCP Fragmentation flood protect now (Y/N)?:  ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r   SETTING      | Do you want to enable TCP Fragmentation flood protect now (Y/N)?:   ");
    }
  }
  ReturnMode2(serial_port);
}

void set_HTTP_IP_Table(int serial_port)
{
start_http:
  char key = 0;
  char enter = '\r';
  printf("\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t| Key Enter | Please choose 1 option below:                                                                              |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     1.    | Show Attacker's IP Table                                                                                 	 |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     2.    | Add IPv4 in Attacker Table                                                                             	 |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | Add IPv6 in Attacker Table                                                                             	 |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Clear IPv4 in Attacker Table                                                                               |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     5.    | Clear IPv6 in Attacker Table                                                                               |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     6.    | Exit                                                                                                       |\r\n");
  printf("\t\t+-----------+------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\tPlease choose mode:  ");

  while (1)
  {
    scanf("%c", &key);

    if (key == '1' || key == '2' || key == '3' || key == '4' || key == '5' || key == '6')
    {
      break;
    }
    else if (key != '1' || key != '2' || key != '3' || key != '4' || key != '5' || key != '6')
    {
      printf("\r     SETTING     | --> Please choose Mode: ");
    }
  }
  if (key == '1')
  {
  }
  else if (key == '2')
  {
    SetIPv4Block(serial_port);
    system("clear");
    display_logo1();
    goto start_http;
  }
  else if (key == '3')
  {
    SetIPv6Block(serial_port);
    system("clear");
    display_logo1();
    goto start_http;
  }
  else if (key == '4')
  {
    RemoveIPv4Block(serial_port);
    system("clear");
    display_logo1();
    goto start_http;
  }
  else if (key == '5')
  {
    RemoveIPv6Block(serial_port);
    system("clear");
    display_logo1();
    goto start_http;
  }
  else if (key == '6')
  {
  }
  ReturnMode2(serial_port);
}

void SetHTTPDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'p';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n   SETTING       |  Do you want to enable HTTP GET flood protect now (Y/N)?: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       |  Do you want to enable HTTP GET flood protect now (Y/N)?:  ");
    }
  }
  ReturnMode2(serial_port);
}

// Enable/Disnable HTTPS
void SetHTTPSDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 0xFF;

  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n   SETTING       |  Do you want to enable HTTPS GET flood protect now (Y/N)?: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       |  Do you want to enable HTTPS GET flood protect now (Y/N)?:  ");
    }
  }
  ReturnMode2(serial_port);
}
// Anti_UDP fragment
void SetUDPFragDefender(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = 'o';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n   SETTING       |  Do you want to enable UDP Fragmentation flood protect now (Y/N)?: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      write(serial_port, &enter, sizeof(enter));
      usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r  SETTING       |  Do you want to enable UDP Fragmentation flood protect now (Y/N)?:  ");
    }
  }
  ReturnMode2(serial_port);
}

void send_ipv4_address(int serial_port)
{
  // system("clear");
  char ip_address[16];
  char enter[] = {'\r'};
  while (1)
  {
    //  printf("Nh?p d?a ch? IP: ");
    scanf("%15s", ip_address);
    if (validate_ip_address(ip_address))
    {
      break;
    }
    else
    {
      printf(" Invalid! Please input!!!");
    }
  }
  // process_ip(LOGFILE_HTTP_IPv4, ip_address);
  int n = strlen(ip_address);
  for (int i = 0; i < n; i++)
  {
    char data[2] = {ip_address[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void send_ipv4_address_http_add(int serial_port)
{
  // system("clear");
  char ip_address[16];
  char enter[] = {'\r'};
  while (1)
  {
    //  printf("Nh?p d?a ch? IP: ");
    scanf("%15s", ip_address);
    if (validate_ip_address(ip_address))
    {
      break;
    }
    else
    {
      printf(" Invalid! Please input!!!");
    }
  }
  process_ip(LOGFILE_HTTP_IPv4, ip_address);
  int n = strlen(ip_address);
  for (int i = 0; i < n; i++)
  {
    char data[2] = {ip_address[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void send_ipv4_address_http_remove(int serial_port)
{
  // system("clear");
  char ip_address[16];
  char enter[] = {'\r'};
  while (1)
  {
    //  printf("Nh?p d?a ch? IP: ");
    scanf("%15s", ip_address);
    if (validate_ip_address(ip_address))
    {
      break;
    }
    else
    {
      printf(" Invalid! Please input!!!");
    }
  }
  remove_ip_from_file(LOGFILE_HTTP_IPv4, ip_address);
  remove_ip_HTTP_from_hash(ip_address);
  int n = strlen(ip_address);
  for (int i = 0; i < n; i++)
  {
    char data[2] = {ip_address[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}
int validate_ip_address(const char *ip_address)
{
  regex_t regex;
  int reti;

  // Bi?u th?c ch nh quy d? ki?m tra d?nh d?ng IP
  const char *pattern = "^([0-9]{1,3}\\.){3}[0-9]{1,3}$";

  // Bi n d?ch bi?u th?c ch nh quy
  reti = regcomp(&regex, pattern, REG_EXTENDED);
  if (reti)
  {
    printf("Could not compile regex\n");
    return 0; // Kh ng h?p l? n?u regex kh ng bi n d?ch du?c
  }

  // So kh?p d?a ch? IP v?i bi?u th?c ch nh quy
  reti = regexec(&regex, ip_address, 0, NULL, 0);

  // Gi?i ph ng b? nh? du?c s? d?ng b?i bi?u th?c ch nh quy
  regfree(&regex);

  if (reti)
  {
    return 0; // Kh ng h?p l? n?u d?nh d?ng kh ng kh?p
  }

  // N?u d?nh d?ng h?p l?, ki?m tra gi  tr? c?a t?ng ph?n
  int octet[4];
  sscanf(ip_address, "%d.%d.%d.%d", &octet[0], &octet[1], &octet[2], &octet[3]);

  for (int i = 0; i < 4; i++)
  {
    if (octet[i] < 0 || octet[i] > 255)
    {
      return 0;
    }
  }

  return 1;
}

int is_valid_mac_address(const char *mac)
{
  if (strlen(mac) != 17)
    return 0;

  for (int i = 0; i < 17; i++)
  {
    if ((i + 1) % 3 == 0)
    {
      if (mac[i] != ':' && mac[i] != '-')
        return 0; // cho phép cả ":" và "-"
    }
    else
    {
      if (!isxdigit(mac[i]))
        return 0; // phải là ký tự hex: 0-9, a-f, A-F
    }
  }
  return 1;
}

void send_ipv6_address(int serial_port)
{
  char ipv6_address[40];
  char full_ipv6_address[40];
  char enter[] = {'\r'};
  struct in6_addr addr;
  unsigned short ipv6_segments[8];

  while (1)
  {
    scanf("%39s", ipv6_address);
    if (inet_pton(AF_INET6, ipv6_address, &addr) == 1)
    {
      for (int i = 0; i < 8; i++)
      {
        ipv6_segments[i] = (addr.s6_addr[i * 2] << 8) | addr.s6_addr[i * 2 + 1];
      }
      snprintf(full_ipv6_address, sizeof(full_ipv6_address),
               "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
               ipv6_segments[0], ipv6_segments[1], ipv6_segments[2], ipv6_segments[3],
               ipv6_segments[4], ipv6_segments[5], ipv6_segments[6], ipv6_segments[7]);
      break;
    }
    else
    {
      printf("Invalid IPv6 address. Please re-enter:");
    }
  }
  int n = strlen(full_ipv6_address);
  for (int i = 0; i < n; i++)
  {
    char data = full_ipv6_address[i];
    send_data(serial_port, &data, sizeof(data));
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}
void send_ipv6_address_http_add(int serial_port)
{
  char ipv6_address[40];
  char full_ipv6_address[40];
  char enter[] = {'\r'};
  struct in6_addr addr;
  unsigned short ipv6_segments[8];

  while (1)
  {
    scanf("%39s", ipv6_address);
    if (inet_pton(AF_INET6, ipv6_address, &addr) == 1)
    {
      for (int i = 0; i < 8; i++)
      {
        ipv6_segments[i] = (addr.s6_addr[i * 2] << 8) | addr.s6_addr[i * 2 + 1];
      }
      snprintf(full_ipv6_address, sizeof(full_ipv6_address),
               "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
               ipv6_segments[0], ipv6_segments[1], ipv6_segments[2], ipv6_segments[3],
               ipv6_segments[4], ipv6_segments[5], ipv6_segments[6], ipv6_segments[7]);
      break;
    }
    else
    {
      printf("Invalid IPv6 address. Please re-enter:");
    }
  }
  process_ip(LOGFILE_HTTP_IPv6, full_ipv6_address);
  int n = strlen(full_ipv6_address);
  for (int i = 0; i < n; i++)
  {
    char data = full_ipv6_address[i];
    send_data(serial_port, &data, sizeof(data));
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void send_ipv6_address_http_remove(int serial_port)
{
  char ipv6_address[40];
  char full_ipv6_address[40];
  char enter[] = {'\r'};
  struct in6_addr addr;
  unsigned short ipv6_segments[8];

  while (1)
  {
    scanf("%39s", ipv6_address);
    if (inet_pton(AF_INET6, ipv6_address, &addr) == 1)
    {
      for (int i = 0; i < 8; i++)
      {
        ipv6_segments[i] = (addr.s6_addr[i * 2] << 8) | addr.s6_addr[i * 2 + 1];
      }
      snprintf(full_ipv6_address, sizeof(full_ipv6_address),
               "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
               ipv6_segments[0], ipv6_segments[1], ipv6_segments[2], ipv6_segments[3],
               ipv6_segments[4], ipv6_segments[5], ipv6_segments[6], ipv6_segments[7]);
      break;
    }
    else
    {
      printf("Invalid IPv6 address. Please re-enter:");
    }
  }
  remove_ip_from_file(LOGFILE_HTTP_IPv6, full_ipv6_address);
  remove_ip_HTTP_from_hash(full_ipv6_address);
  int n = strlen(full_ipv6_address);
  for (int i = 0; i < n; i++)
  {
    char data = full_ipv6_address[i];
    send_data(serial_port, &data, sizeof(data));
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

// Remove IP from file
void remove_ip_from_file(const char *filename, const char *ip)
{
  FILE *file = fopen(filename, "r");
  if (file == NULL)
  {
    perror("Error opening file");
    return;
  }

  char **lines = NULL;
  size_t count = 0;
  char buffer[256];

  while (fgets(buffer, sizeof(buffer), file))
  {
    lines = realloc(lines, (count + 1) * sizeof(char *));
    lines[count] = strdup(buffer);
    count++;
  }
  fclose(file);

  file = fopen(filename, "w");
  if (file == NULL)
  {
    perror("Error opening file for writing");
    for (size_t i = 0; i < count; i++)
    {
      free(lines[i]);
    }
    free(lines);
    return;
  }

  for (size_t i = 0; i < count; i++)
  {
    if (strstr(lines[i], ip) == NULL)
    {
      fputs(lines[i], file);
    }
    free(lines[i]);
  }
  free(lines);

  fclose(file);
}

// Remove IP HTTP from hash
void remove_ip_HTTP_from_hash(const char *ip)
{
  if (g_hash_table_size(ip_table) == 0)
  {
    return;
  }
  // remove  ip hash
  g_hash_table_remove(ip_table, ip);
}

// void Check_Table_IPv4()
// {

//   if (ipV4_1 != NULL && ipV4_2 != NULL && ipV4_3 != NULL && ipV4_4 != NULL)
//   {
//     printf("\n\n The ipv4 protection table is full!!!");
//   }
//   else
//   {
//   }
// }
void SetIPv4Target(int serial_port)
{
  char key_mode = '4';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(100000);
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv4 address want to protect : ");
  send_ipv4_address(serial_port);
  ReturnMode2(serial_port);
}

void SetIPv6Target(int serial_port)
{
  char key_mode = 'R';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv6 address want to protect : ");
  send_ipv6_address(serial_port);
  ReturnMode2(serial_port);
}

void SetIPv4Block(int serial_port)
{
  char key_mode = 'T';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv4 address want to block : ");
  send_ipv4_address_http_add(serial_port);
}

void SetIPv6Block(int serial_port)
{
  char key_mode = '{';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv6 address want to block : ");
  send_ipv6_address_http_add(serial_port);
}

void RemoveIPv4Block(int serial_port)
{
  char key_mode = 'X';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv4 address want to remove IP from block table : ");
  send_ipv4_address_http_remove(serial_port);
}

void RemoveIPv6Block(int serial_port)
{
  char key_mode = '}';
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Enter Server IPv6 address want to remove IP from block table : ");
  send_ipv6_address_http_remove(serial_port);
}

void ReturnMode2(int serial_port)
{
  char key;
  char enter = '\r';
  system("clear");
  display_logo1();
  display_table(serial_port);
  // printf("\r\n\t\t|                                                                                                                                                                        |\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Return to the device configuration menu? (Y):");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y')
    {
      break;
    }
    if (key != 'y' || key != 'Y')
    {
      printf("\r    SETTING     | Return to the device configuration menu? (Y): ");
    }
  }
}

void ReturnMode2b(int serial_port)
{
  system("clear");
  display_logo1();
  display_table(serial_port);
  char key;
  char enter = '\r';
  // printf("\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Return to the device configuration menu? (Y):");
  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y')
    {
      break;
    }
    if (key != 'y' || key != 'Y')
    {
      printf("\r    SETTING     | Return to the device configuration menu? (Y): ");
    }
  }
}
void printf_uart(int serial_port)
{
  int a = 0;
  char read1[50000];
  while (1)
  {
    memset(&read1, 0, sizeof(read1));
    int num_bytes = read(serial_port, &read1, sizeof(read1));
    printf("%s", read1);
    a = a + 1;
    if (read1[num_bytes - 1] == '*')
    {
      break;
    }
  }
}

void printf_uart1(int serial_port)
{

  struct winsize w;
  int max_lines, current_line = 0;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  max_lines = w.ws_row - 3;
  char key2, ch, key3;
  bool rs = false;
  struct statvfs stat1;
  full_sd1 = false;
  system("clear");
start:
  printf("\033[1;36m \n\n|\tTime\t\t|  \t\tSource IP\t\t    |  \t\tDest IP\t\t\t       | Source Port\t| Dest Port\t| Protocol\t| \tType\t\t|\tBW\t|\tPKT/s\t|\n\033[0m");

  if (statvfs("/", &stat1) != 0)
  {
    perror("statvfs error");
    pthread_exit(NULL);
  }

  unsigned long total_space = (stat1.f_blocks * stat1.f_frsize);
  unsigned long used_space = (stat1.f_blocks - stat1.f_bfree) * stat1.f_frsize;
  float memory_usage = (float)used_space / total_space * 100;
  float CAPACITY = (float)total_space / (1024 * 1024 * 1024);
  float used_space_gb = (float)used_space / (1024 * 1024 * 1024);

  char read1[50000];
  int ctrl_p_pressed = 0;
  time_t ctrl_p_time;

  char msg10[] = {'\r'};

  while (1)
  {

    if (print_buffer_pos > 0)
    {

      if (current_line >= max_lines - 3)
      {
        system("clear");
        printf("\033[1;36m \n\n|\tTime\t\t|  \t\tSource IP\t\t    |  \t\tDest IP\t\t\t       | Source Port\t| Dest Port\t| Protocol\t| \tType\t\t|\tBW\t|\tPKT/s\t|\n\033[0m");

        current_line = 0;
      }

      printf("%s", print_buffer);
      current_line++;
      fflush(stdout);

      print_buffer_pos = 0;
    }

    if (kbhit())
    {
      ch = getchar();

      if (ch == 16)
      {

        ctrl_p_pressed = 1;
        ctrl_p_time = time(NULL);
      }
    }
    if (ctrl_p_pressed && (time(NULL) - ctrl_p_time >= 1))
    {
      break;
    }

    if ((full_sd == true && full_sd1 == false))
    {
      do
      {
        printf("\r\n | ALLOWED THRESHOLD IS EXCEEDED, PLEASE CHECK LOGFILE !!! ");
        printf("\r\n | CAPACITY: %.2f GB (100 %)   |  Used space: %.2f GB (%.2f%%)    | Free space: %.2f GB (%.2f%%)", CAPACITY, used_space_gb, 100 - memory_usage, CAPACITY - used_space_gb, memory_usage);
        printf("\r\n | Do you want check log file (Y/N)? :  ");
        scanf(" %c", &key2);
        if ((key2 == 'Y') || (key2 == 'y'))
        {
          break;
        }
        else if ((key2 == 'N') || (key2 == 'n'))
        {
          break;
        }

      } while (1);
      if ((key2 == 'Y') || (key2 == 'y'))
      {
        Mode_Condition_SDCard(serial_port);
      }
      else if ((key2 == 'N') || (key2 == 'n'))
      {
        full_sd1 = true;

        goto start;
      }
    }
  }

  if (ch == 16)
  {
    system("clear");
    options_mode1(serial_port);
  }
}

void send_array(int serial_port)
{
  char array[10];
  char enter[] = {'\r'};
  int valid_input = 0;

  while (!valid_input)
  {
    scanf("%s", array);
    int num = atoi(array);
    if (num > 65535)
    {
      printf("The value must be less than 65536, Please re-enter: ");
    }
    else
    {
      valid_input = 1;
    }
  }

  int n = strlen(array);
  for (int i = 0; i < n; i++)
  {
    char data[2] = {array[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void send_duration_time(int serial_port)
{
  char key_mode = '%';
  char array[10];
  char enter[] = {'\r'};
  int valid_input = 0;

  while (!valid_input)
  {
    scanf("%s", array);
    int num = atoi(array);
    if (num > 20000000)
    {
      printf("The value must be less than 2s, Please re-enter: ");
    }
    else
    {
      valid_input = 1;
    }
  }

  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(300000);
  int n = strlen(array);
  for (int i = 0; i < n; i++)
  {
    char data[2] = {array[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

int is_valid_date(int day, int month, int year)
{
  int days_in_month[] = {31, 28 + (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12)
    return 0;
  return day >= 1 && day <= days_in_month[month - 1];
}

void send_user_time(int serial_port)
{
  char msg10[] = {'\r'};
  int yy, mm, dd, hh, xx, cc;
  char time_array[11];
  char confirm;
  do
  {

    while (1)
    {
      printf("\r\n\t\t| Input year(yy, ex: 24 for 2024): ");
      scanf("%d", &yy);
      if (yy >= 0 && yy <= 99)
        break;
      printf("\r\n\t\t| Invalid year. Please re-enter:");
    }
    while (1)
    {
      printf("\r\n\t\t| Input month (mm,  01 --> 12): ");
      scanf("%d", &mm);
      if (mm >= 1 && mm <= 12)
        break;
      printf("\r\n\t\t| Invalid month. Please re-enter:");
    }
    while (1)
    {
      printf("\r\n\t\t| Input day (dd, 	01 --> 31): ");
      scanf("%d", &dd);
      //  break;
      if (is_valid_date(dd, mm, 2000 + yy))
        break;
      printf("\r\n\t\t| Invalid day. Please re-enter:");
    }

    while (1)
    {
      printf("\r\n\t\t| Input hour (hh,  01 --> 12): ");
      scanf("%d", &hh);
      //  break;
      if (hh >= 1 && hh <= 12)
        break;
      printf("\r\n\t\t| Invalid hour. Please re-enter: ");
    }

    // Nh?p ph t (xx)
    while (1)
    {
      printf("\r\n\t\t| Input minutes (mm,  00 --> 59): ");
      scanf("%d", &xx);
      if (xx >= 0 && xx <= 59)
        break;
      printf("\r\n\t\t| Invalid minutes. Please re-enter: ");
    }

    // Nh?p gi y (cc)
    while (1)
    {
      printf("\r\n\t\t| Input seconds (ss, 00 --> 59):  ");
      scanf("%d", &cc);
      if (cc >= 0 && cc <= 59)
        break;
      printf("\r\n\t\t| Invalid seconds. Please re-enter:\n ");
    }
    printf("\n\t\t| You entered: %02d-%02d-%02d  %02d:%02d:%02d", yy, mm, dd, hh, xx, cc);
    printf("\n\t\t| Are you sure? (Y/N): ");
    scanf(" %c", &confirm);
  } while (confirm != 'Y' && confirm != 'y');

  time_array[0] = '0' + (yy / 10);
  time_array[1] = '0' + (yy % 10);
  time_array[2] = '0' + (mm / 10); // Ch? s? d?u ti n c?a mm
  time_array[3] = '0' + (mm % 10); // Ch? s? th? hai c?a mm
  time_array[4] = '0' + (dd / 10); // Ch? s? d?u ti n c?a dd

  time_array[5] = '0' + (dd % 10);  // Ch? s? th? hai c?a dd
  time_array[6] = '0' + (hh / 10);  // Ch? s? d?u ti n c?a hh
  time_array[7] = '0' + (hh % 10);  // Ch? s? th? hai c?a hh
  time_array[8] = '0' + (xx / 10);  // Ch? s? d?u ti n c?a xx
  time_array[9] = '0' + (xx % 10);  // Ch? s? th? hai c?a xx
  time_array[10] = '0' + (cc / 10); // Ch? s? d?u ti n c?a cc
  time_array[11] = '0' + (cc % 10); // Ch? s? th? hai c?a cc

  for (int i = 0; i < 12; i++)
  {
    usleep(100000);
    send_data(serial_port, &time_array[i], sizeof(char));
    // printf("   g?i : %s\n", time_array[i]);
    // printf("20%d - %d - %d  %d-%d-%d", yy,mm,dd,hh,xx,cc);
  }

  //  printf("\t\t=============================");
  //    printf("\t\t20%d - %d - %d  %d:%d:%d", yy,mm,dd,hh,xx,cc);

  sleep(1);
  write(serial_port, msg10, sizeof(msg10));
}

void change_info_acc_admin_mode(int serial_port)
{
start:
  system("clear");
  char key = 0;
  char enter = '\r';
  display_logo1();
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n ==> Mode 3 is selected.                                                                                                                                                                                     |");
  printf("\r\n                                                                                                                                                                                                             |");
  printf("\r\n================+===========+==========================================+=====================================================================================================================================+");
  printf("\r\n    DISPLAY     |           |                                          |                                                                                                                                     |");
  printf("\r\n\t\t| Key Enter |           Choose 1 option below:         |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     0.    | Change password user account.            |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     1.    | Add new user account.                    |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     2.    | Display saved user account.              |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     3.    | Delete user account.                     |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     4.    | Reset all user accounts.                 |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     5.    | Change root password.                    |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     6.    | Load default setting from manufacturer.  |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t|     7.    | ==> Exit.                                |                                                                                                                                     |");
  printf("\r\n\t\t+-----------+------------------------------------------+                                                                                                                                     |");
  printf("\r\n\t\t+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n================+============================================================================================================================================================================================+");
  printf("\r\n    SETTING     |  --> Your choice: ");

  while (1)
  {
    scanf("%c", &key);
    if (key == '0' || key == '1' || key == '2' || key == '3' || key == '4' || key == '5' || key == '6' || key == '7')
    {
      break;
    }
    if (key != '0' || key != '1' || key != '2' || key != '3' || key != '4' || key != '5' || key != '6' || key != '7')
    {
      printf("\r     SETTING     | --> Your choice: ");
    }
  }

  if (key == '0')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    check_username_change_pass(serial_port);
    goto start;
  }
  else if (key == '1')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    add_acount(serial_port);
    goto start;
  }
  else if (key == '2')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
    goto start;
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    delete_account(serial_port);
    goto start;
  }
  else if (key == '4')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    reset_account(serial_port);
    goto start;
  }
  else if (key == '5')
  {
    system("clear");
    display_logo1();
    display_account(serial_port);
    change_root(serial_port);
    goto start;
  }

  else if (key == '6')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    setload_default(serial_port);
    goto start;
  }
  else if (key == '7')
  {
    // DisplayTable();
    // printf_uart(serial_port);
    // SaveEEPROM(serial_port);
  }
}
void ReturnMode3()
{
  char key;
  char enter = '\r';
  // system("clear");
  // display_logo2();
  // display_account(serial_port);

  printf("\r\n================+============================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Return to the device configuration menu? (Y): ");

  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y')
    {
      system("clear");
      // write(serial_port, &key, sizeof(key));
      // usleep(100000);
      // write(serial_port, &enter, sizeof(enter));
      // usleep(1000000);
      break;
    }
    if (key != 'y' || key != 'Y')
    {
      printf("\r    SETTING     | Return to the device configuration menu? (Y): ");
    }
  }

  // char *data = receive_data(serial_port);
  // if (data == NULL)
  // {
  //   return;
  // }
  // if ((strchr(data, 'X') != NULL))
  // {
  //   change_info_acc_admin_mode(serial_port);
  // }
}

void add_acount(int serial_port)
{
  // char key_mode = '+';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  input_and_send_account1(serial_port);
  char *data = receive_data(serial_port);
  if (data == NULL)
  {
    printf("Error receiving data\n");
    return;
  }
  if ((strchr(data, 'Y') != NULL))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t|                                               Successfully !!!                                                                                                                             |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    usleep(2000000);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
  else if ((strchr(data, 'F') != NULL))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t| Cannot add new user. The number of user accounts is full!.                                                                                                                                 |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    usleep(2000000);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
  else if ((strchr(data, 'V') != NULL))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t| Cannot add new user. Account already exists!.                                                                                                                                              |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t|                                                                                                                                                                                            |");
    printf("\r\n\t\t+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
    usleep(2000000);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
  if ((strchr(data, 'G') != NULL))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t| Change Password Successfully!.                                                                                                                                                             |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    usleep(2000000);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
}
void delete_account(int serial_port)
{
  // char key_mode = ')';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  input_and_send_username(serial_port);
  char *data = receive_data(serial_port);
  if (data == NULL)
  {
    printf("Error receiving data\n");
    return;
  }
  if ((strchr(data, 'Y') != NULL))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t|                                               Successfully !!!                                                                                                                             |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    sleep(2);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
  else if ((strchr(data, 'F')))
  {
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    printf("\r\n\t\t|                                               Wrong user account.                                                                                                                          |");
    printf("\r\n\t\t+============================================================================================================================================================================================+");
    sleep(2);
    system("clear");
    display_logo1();
    display_account(serial_port);
    ReturnMode3();
  }
}
void DisplayAccount(int serial_port)
{
  ReturnMode3(serial_port);
}

void reset_account(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = '[';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  printf("\r\n================+============================================================================================================================================================================================+");
  printf("\r\n    SETTING     | Do you want to reset all user account? (Y): ");

  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y')
    {
      write(serial_port, &key_mode, sizeof(key_mode));
      usleep(100000);
      write(serial_port, &key_enter, sizeof(key_enter));
      usleep(500000);
      write(serial_port, &key, sizeof(key));
      usleep(100000);
      // write(serial_port,&enter,sizeof(enter));
      // usleep(1000000);
      break;
    }
    if (key == 'n' || key == 'N')
    {
      break;
    }

    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {
      printf("\r    SETTING     | Do you want to reset all user account? (Y): ");
    }
  }
  system("clear");
  display_logo1();
  display_account(serial_port);
  ReturnMode3();
  // char *data = receive_data(serial_port);
  // if (data == NULL)
  // {
  //   printf("Error receiving data\n");
  //   return;
  // }
  // if ((strchr(data, 'R') != NULL))
  // {
  //   system("clear");
  //   ReturnMode3(serial_port);
  // }
}

void change_root(int serial_port)
{
  // char key_mode = ';';
  // write(serial_port, &key_mode, sizeof(key_mode));
  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  input_and_send_password(serial_port);
  // char *data = receive_data(serial_port);
  // if (data == NULL)
  // {
  //   printf("Error receiving data\n");
  //   return;
  // }
  // if ((strchr(data, 'N') != NULL) || (strchr(data, 'n')))
  // {
  //   system("clear");
  //   ReturnMode3(serial_port);
  // }
  system("clear");
  display_logo1();
  display_account(serial_port);
  ReturnMode3();
}

void setload_default(int serial_port)
{
  char key;
  char enter = '\r';
  char key_mode = ']';

  printf("\r\n================+============================================================================================================================================================================================+\n");
  printf("\r\n    SETTING     | Do you want to load default device configuration from manufacturer? (Y/N): ");

  while (1)
  {
    scanf("%c", &key);
    if (key == 'y' || key == 'Y' || key == 'n' || key == 'N')
    {

      write(serial_port, &key_mode, sizeof(key_mode));
      usleep(100000);
      write(serial_port, &key_enter, sizeof(key_enter));
      usleep(500000);

      write(serial_port, &key, sizeof(key));
      usleep(100000);

      break;
    }
    if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
    {

      printf("\r   SETTING     | Do you want to load default device configuration from manufacturer? (Y/N): ");
    }
  }
  system("clear");
  display_logo1();
  display_table(serial_port);
  ReturnMode3();
}

int kbhit(void)
{
  struct termios oldt, newt;
  int ch;
  int oldf;

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ICANON;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

  ch = getchar();

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  fcntl(STDIN_FILENO, F_SETFL, oldf);

  if (ch != EOF)
  {
    ungetc(ch, stdin);
    return 1;
  }

  return 0;
}
// Ham cau hinh port uart
int configure_serial_port(const char *device, int baud_rate)
{
  int serial_port = open(device, O_RDWR);
  struct termios tty;
  if (tcgetattr(serial_port, &tty) != 0)
  {
    printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
    return 1;
  }
  tty.c_cflag &= ~PARENB;        // Clear parity bit, disabling parity (most common)
  tty.c_cflag &= ~CSTOPB;        // Clear stop field, only one stop bit used in communication (most common)
  tty.c_cflag &= ~CSIZE;         // Clear all bits that set the data size
  tty.c_cflag |= CS8;            // 8 bits per byte (most common)
  tty.c_cflag &= ~CRTSCTS;       // Disable RTS/CTS hardware flow control (most common)
  tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

  tty.c_lflag &= ~ICANON;
  tty.c_lflag &= ~ECHO;                                                        // Disable echo
  tty.c_lflag &= ~ECHOE;                                                       // Disable erasure
  tty.c_lflag &= ~ECHONL;                                                      // Disable new-line echo
  tty.c_lflag &= ~ISIG;                                                        // Disable interpretation of INTR, QUIT and SUSP
  tty.c_iflag &= ~(IXON | IXOFF | IXANY);                                      // Turn off s/w flow ctrl
  tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL); // Disable any special handling of received bytes

  tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
  tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
  // tty.c_oflag &= ~OXTABS; // Prevent conversion of tabs to spaces (NOT PRESENT ON LINUX)
  // tty.c_oflag &= ~ONOEOT; // Prevent removal of C-d chars (0x004) in output (NOT PRESENT ON LINUX)

  tty.c_cc[VTIME] = 10; // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
  tty.c_cc[VMIN] = 0;

  // Set in/out baud rate
  cfsetispeed(&tty, baud_rate);
  cfsetospeed(&tty, baud_rate);

  // Save tty settings, also checking for error
  if (tcsetattr(serial_port, TCSANOW, &tty) != 0)
  {
    printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
    return 1;
  }
  return serial_port;
}
// Ham nhap account
void input_and_send_account(int serial_port)
{
  char enter[] = {'\r'};
  char username[17];
  char password[17];
  int valid_input = 0;

  while (!valid_input)
  {
    printf("\r\n ===============+============================================================================================================================================================================================+");
    printf("\r\n      LOG IN    | Username: ");
    scanf("%16s", username);
    printf("\r\n\t\t| Password: ");
    scanf("%16s", password);

    if (strlen(username) > 16 || strlen(password) > 16)
    {
      printf("The account or password exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }

  // while (getchar() != '\n')
  //   ;
  // getchar();
  write(serial_port, &key_check_account, sizeof(key_check_account));
  usleep(1000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_username = strlen(username);
  for (int i = 0; i < n_username; i++)
  {
    usleep(50000);
    char data[2] = {username[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  usleep(500000);
  write(serial_port, enter, sizeof(enter));

  int n_password = strlen(password);
  for (int i = 0; i < n_password; i++)
  {
    usleep(50000);
    char data[2] = {password[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  usleep(500000);
  write(serial_port, enter, sizeof(enter));
}
void input_and_send_account1(int serial_port)
{
  char key_mode = '+';
  char enter[] = {'\r'};
  char username[17];
  char password[17];
  int valid_input = 0;

  while (!valid_input)
  {
    printf("\r\n ===============+============================================================================================================================================================================================+");
    printf("\r\n    Account     | Enter Username: ");
    scanf("%16s", username);
    printf("\r\n\t\t| Enter Password: ");
    scanf("%16s", password);

    if (strlen(username) > 16 || strlen(password) > 16)
    {
      printf("The account or password exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }

  // while (getchar() != '\n')
  //   ;
  // getchar();
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_username = strlen(username);
  for (int i = 0; i < n_username; i++)
  {
    usleep(50000);
    char data[2] = {username[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));

  int n_password = strlen(password);
  for (int i = 0; i < n_password; i++)
  {
    usleep(50000);
    char data[2] = {password[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}
void input_and_send_account2(int serial_port)
{
  char key_mode = '(';
  char enter[] = {'\r'};
  char username[17];
  char password[17];
  int valid_input = 0;

  while (!valid_input)
  {
    printf("\r\n ===============+============================================================================================================================================================================================+");
    printf("\r\n    Account     | Enter Username: ");
    scanf("%16s", username);
    printf("\r\n\t\t| Enter Password: ");
    scanf("%16s", password);

    if (strlen(username) > 16 || strlen(password) > 16)
    {
      printf("The account or password exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }

  // while (getchar() != '\n')
  //   ;
  // getchar();
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_username = strlen(username);
  for (int i = 0; i < n_username; i++)
  {
    usleep(50000);
    char data[2] = {username[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));

  int n_password = strlen(password);
  for (int i = 0; i < n_password; i++)
  {
    usleep(50000);
    char data[2] = {password[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}
// delete acount
void input_and_send_username(int serial_port)
{
  char key_mode = ')';

  char enter[] = {'\r'};
  char username[17];
  int valid_input = 0;

  while (!valid_input)
  {
    printf("\r\n ===============+============================================================================================================================================================================================+");
    printf("\r\n    Account     | Enter an account username account need to be deleted: ");
    scanf("%16s", username);

    if (strlen(username) > 16)
    {
      printf("The username exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }
  // while (getchar() != '\n')
  //   ;
  // getchar();
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_username = strlen(username);
  for (int i = 0; i < n_username; i++)
  {
    usleep(50000);
    char data[2] = {username[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}

void input_and_send_password(int serial_port)
{

  char key_mode = ';';

  // usleep(100000);
  // write(serial_port, &key_enter, sizeof(key_enter));
  // usleep(100000);
  char enter[] = {'\r'};
  char password[17];
  int valid_input = 0;

  while (!valid_input)
  {
    printf("\r\n ===============+============================================================================================================================================================================================+");
    printf("\r\n    Account     | Enter new password for root: ");
    scanf("%16s", password);

    if (strlen(password) > 16)
    {
      printf("The username exceeds 16 characters. Please re-enter.\n");
    }
    else
    {
      valid_input = 1;
    }
  }
  // while (getchar() != '\n')
  //   ;
  // getchar();
  write(serial_port, &key_mode, sizeof(key_mode));
  usleep(100000);
  write(serial_port, &key_enter, sizeof(key_enter));
  usleep(200000);
  int n_password = strlen(password);
  for (int i = 0; i < n_password; i++)
  {
    usleep(50000);
    char data[2] = {password[i], '\0'};
    send_data(serial_port, data, sizeof(data) - 1);
  }
  sleep(1);
  write(serial_port, enter, sizeof(enter));
}
// Ham gui du lieu tu uart
int send_data(int serial_port, const char *data, size_t size)
{
  int num_byte = write(serial_port, data, size);
  if (num_byte < 0)
  {
    printf("Error reading: %s", strerror(errno));
    return 1;
  }
  return num_byte;
}

// Ham nhan du lieu tu uart
char *receive_data(int serial_port)
{
  static char read_buf[256];
  memset(read_buf, '\0', sizeof(read_buf));

  int num_bytes = read(serial_port, &read_buf, sizeof(read_buf));
  if (num_bytes < 0)
  {
    printf("Error reading: %s\n", strerror(errno));
    return NULL;
  }

  // read_buf[num_bytes] = '\0';
  return read_buf;
}

//
void Mode_Condition_SDCard(int serial_port)
{
  system("clear");
  display_logo1();
  char key, key1;
  char enter = '\r';
  printf("\r\n                                                                                                                                                                                                             |");
  display_setting_user1();
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
  printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     1:    | Display Flood LogFile                                                                                                                                                                |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     2:    | Display Normal LogFile                                                                                                                                                               |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     3:    | Exit                                                                                                                                                                          |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ----------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========================================================================================================================================================================================+\n");

  while (1)
  {
    scanf("%c", &key);
    if (key == '1')
    {
      display_log_files(LOG_FLOOD_DIR);

      printf("\r\n ================+===========================================================================================================================================================================================+\n");
      printf("\r\n    SETTING     | Press key Y to return!");

      while (1)
      {
        scanf("%c", &key1);
        if (key1 == 'y' || key1 == 'Y')
        {
          system("clear");
          display_logo1();
          Mode_Condition_SDCard(serial_port);
        }
        if (key1 != 'y' || key1 != 'Y')
        {
          printf("\r    SETTING     | Press key Y to return! ");
        }
      }
    }
    if (key == '2')
    {
      display_log_files(LOG_NORMAL_DIR);

      printf("\r\n ================+===========================================================================================================================================================================================+\n");
      printf("\r\n    SETTING     | Press key Y to return!");

      while (1)
      {
        scanf("%c", &key1);
        if (key1 == 'y' || key1 == 'Y')
        {
          system("clear");
          display_logo1();
          Mode_Condition_SDCard(serial_port);
        }
        if (key1 != 'y' || key1 != 'Y')
        {
          printf("\r    SETTING     | Press key Y to return! ");
        }
      }
    }
    if (key == '3')
    {
      options_mode1(serial_port);
      break;
    }

    if (key != '1' || key != '2' || key != '3')
    {
      printf("\r     SETTING     | --> Please choose Mode: ");
    }
  }
}

void Mode_Condition_SDCard_User(int serial_port)
{
start:
  system("clear");
  display_logo1();
  char key, key1;
  char key3 = 'E';
  char enter = '\r';
  printf("\r\n                                                                                                                                                                                                             |");
  display_setting_user();
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
  printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     1:    | Display Flood logfile                                                                                                                                                              |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     2:    | Display Normal logfile                                                                                                                                                              |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     3:    | Change time counter                                                                                                                                                           |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     4:    | Exit                                                                                                                                                                          |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ====+===========+===========================================================================================================================================================================================+");
  printf("\r\n\t\t |  SETTING  | --> Please choose Mode: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == '1')
    {
      display_log_files(LOG_FLOOD_DIR);
      printf("\r\n ===============+============================================================================================================================================================================================+");
      printf("\r\n    Press Y to continue... ");
      while (1)
      {
        scanf("%c", &key1);
        if (key1 == 'y' || key1 == 'Y')
        {
          break;
        }
        if (key1 != 'y' || key1 != 'Y')
        {
          // printf("\r    SETTING     | Return? (Y): ");
        }
      }
      break;
    }
    else if (key == '2')
    {
      display_log_files(LOG_NORMAL_DIR);
      printf("\r\n ===============+============================================================================================================================================================================================+");
      printf("\r\n    Press Y to continue... ");
      while (1)
      {
        scanf("%c", &key1);
        if (key1 == 'y' || key1 == 'Y')
        {
          break;
        }
        if (key1 != 'y' || key1 != 'Y')
        {
          // printf("\r    SETTING     | Return? (Y): ");
        }
      }
      break;
    }
    else if (key == '3')
    {
      break;
    }
    else if (key == '4')
    {
      break;
    }

    // if (key != '1' || key != '2' || key != '3')
    //{
    //   printf("\r\t\t |SETTING    | --> Please choose Mode: ");
    // }
  }
  if (key == '3')
  {
    update_threshold_time_counter();
    goto start;
  }
  if (key == '1' || key == '2')
  {
    goto start;
  }
}
void Mode_Condition_SDCard_Admin(int serial_port)
{
start:
  system("clear");
  display_logo1();
  char key, key2;
  char key3 = 'E';
  char enter = '\r';
  display_setting_admin();
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n     DISPLAY     |           |                                                                                                                                                                               |");
  printf("\r\n\t\t | Key Enter |                  Mode                                                                                                                                                         |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     1:    | Display Flood log file                                                                                                                                                              |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     2:    | Display Normal log file                                                                                                                                                              |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     3:    | Delete Flood log file                                                                                                                                                               |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     4:    | Delete Normal log file                                                                                                                                                               |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     5:    | Change log file saving mode                                                                                                                                                   |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     6:    | Change the threshold for saving log file                                                                                                                                      |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     7:    | Change time counter                                                                                                                                                           |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     8:    | Change duration time export                                                                                                                                                   |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t |     9:    | Exit                                                                                                                                                                          |");
  printf("\r\n\t\t +-----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========================================================================================================================================================================================+\n");
  printf("\r\n\t\t |SETTING    | --> Please choose Mode: ");
  while (1)
  {
    scanf("%c", &key);
    if (key == '1')
    {
      display_log_files(LOG_FLOOD_DIR);
      printf("\r\n ================+===========================================================================================================================================================================================+\n");
      printf("\r\n    SETTING      | Press Y to return ! ");
      while (1)
      {
        scanf("%c", &key2);
        if (key2 == 'y' || key2 == 'Y')
        {
          system("clear");
          display_logo1();
          break;
        }
        if (key2 != 'y' || key2 != 'Y')
        {
          printf("\r    SETTING     | Press Y to return ! ");
        }
      }
      goto start;
    }
    if (key == '2')
    {
      display_log_files(LOG_NORMAL_DIR);
      printf("\r\n ================+===========================================================================================================================================================================================+\n");
      printf("\r\n    SETTING      | Press Y to return ! ");
      while (1)
      {
        scanf("%c", &key2);
        if (key2 == 'y' || key2 == 'Y')
        {
          system("clear");
          display_logo1();
          break;
        }
        if (key2 != 'y' || key2 != 'Y')
        {
          printf("\r    SETTING     | Press Y to return ! ");
        }
      }
      goto start;
    }
    if (key == '3')
    {
      display_log_files(LOG_FLOOD_DIR);
      delete_log_file(LOG_FLOOD_DIR);
      goto start;
    }
    if (key == '4')
    {
      display_log_files(LOG_NORMAL_DIR);
      delete_log_file(LOG_NORMAL_DIR);
      goto start;
    }
    if (key == '5')
    {
      update_mode_auto_manual();
      sleep(2);
      goto start;
    }
    if (key == '6')
    {
      update_threshold_SDCard();
      sleep(2);
      goto start;
    }
    if (key == '7')
    {
      update_threshold_time_counter();
      sleep(2);
      goto start;
    }
    if (key == '8')
    {
      SetDurationTime(serial_port);
      sleep(2);
      goto start;
    }
    if (key == '9')
    {
      break;
    }
    if (key != '1' || key != '2' || key != '3' || key != '4' || key != '5' || key != '6' || key != '7' || key != '8' || key != '9')
    {
      printf("\r\t\t |SETTING    | --> Please choose Mode: ");
    }
  }
}
void read_config_mode_save_logfile()
{
  FILE *config_fp = fopen(AUTO_MANUAL_CONFIG_FILE, "r");
  if (config_fp == NULL)
  {
    config_fp = fopen(AUTO_MANUAL_CONFIG_FILE, "w");
    if (config_fp == NULL)
    {
      printf("Error creating config file: %s\n", AUTO_MANUAL_CONFIG_FILE);
      return;
    }
    fprintf(config_fp, "true");
    fclose(config_fp);
  }
  else
  {
    char value[10];
    fscanf(config_fp, "%s", value);
    fclose(config_fp);

    if (strcmp(value, "true") == 0)
    {
      auto_delete_logs = true;
    }
    else if (strcmp(value, "false") == 0)
    {
      auto_delete_logs = false;
    }
    else
    {
      printf("Invalid value in config file. Using default: true\n");
    }
  }
}

void write_config_mode_save_logfile()
{
  FILE *config_fp = fopen(AUTO_MANUAL_CONFIG_FILE, "w");
  if (config_fp == NULL)
  {
    printf("Error opening config file: %s\n", AUTO_MANUAL_CONFIG_FILE);
    return;
  }

  if (auto_delete_logs)
  {
    fprintf(config_fp, "true");
  }
  else
  {
    fprintf(config_fp, "false");
  }
  fclose(config_fp);
}

void update_mode_auto_manual()
{
  char select;
  // bool new_mode;
  char save_choice;

  printf("\n\t\tSelect the log file saving mode (1/2) ");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n\t\t+============================================================================================================================================================================================+");
  printf("\r\n\t\t| | 1. Auto 							                                                                                                                             |");
  printf("\r\n\t\t| +--------------+-------------+-------------+--------------------+--------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t| | 2. Manual 		                                                                                                                                                                     |");
  printf("\r\n\t\t| +--------------+-------------+-------------+--------------------+--------------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n\t\t| --> Please choose Mode: ");
  while (1)
  {
    scanf("%c", &select);

    if (select == '1' || select == '2')
    {
      printf("\r\n\t\tDo you want to save? (Y/N): ");
      scanf(" %c", &save_choice);

      if (save_choice == 'y' || save_choice == 'Y')
      {
        if (select == '1')
        {
          auto_delete_logs = true;
        }
        else if (select == '2')
        {
          auto_delete_logs = false;
        }

        printf("\r\n\t\tUpdated logging mode successfully");
        write_config_mode_save_logfile();
        break;
      }
      else

        printf("\r\n\t\tUpdate logging mode failed\n");
      break;
    }

    else
    {
      printf("\r\t\t| --> Please choose Mode: ");
    }
  }
}
void display_setting_user()
{
  struct statvfs stat1;
  if (statvfs("/", &stat1) != 0)
  {
    perror("statvfs error");
    pthread_exit(NULL);
  }

  unsigned long total_space = (stat1.f_blocks * stat1.f_frsize);

  unsigned long used_space = (stat1.f_blocks - stat1.f_bfree) * stat1.f_frsize;
  float memory_usage = (float)used_space / total_space * 100;
  float CAPACITY = (float)total_space / (1024 * 1024 * 1024);
  float used_space_gb = (float)used_space / (1024 * 1024 * 1024);
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n\t\t | CAPACITY: %.2f GB (100%)           |  Used space: %.2f GB (%.2f%%)        | Free space: %.2f GB (%.2f%%)             |", CAPACITY, used_space_gb, 100 - memory_usage, CAPACITY - used_space_gb, memory_usage);
  printf("\r\n\t\t +-------------------------------------+--------------------------------------+--------------------------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t | Time counter: %d s                                                                                                                                                                         |", Threshold_time_counter);
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
}
void display_setting_user1()
{
  struct statvfs stat1;
  if (statvfs("/", &stat1) != 0)
  {
    perror("statvfs error");
    pthread_exit(NULL);
  }

  unsigned long total_space = (stat1.f_blocks * stat1.f_frsize);

  unsigned long used_space = (stat1.f_blocks - stat1.f_bfree) * stat1.f_frsize;
  float memory_usage = (float)used_space / total_space * 100;
  float CAPACITY = (float)total_space / (1024 * 1024 * 1024);
  float used_space_gb = (float)used_space / (1024 * 1024 * 1024);

  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n\t\t | | CAPACITY: %.2f GB (100 %)         |  Used space: %.2f GB (%.2f%%)        | Free space: %.2f GB (%.2f%%)", CAPACITY, used_space_gb, 100 - memory_usage, CAPACITY - used_space_gb, memory_usage);
  printf("\r\n\t\t | +----------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------+");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
}
void display_setting_admin()
{
  struct statvfs stat1;
  if (statvfs("/", &stat1) != 0)
  {
    perror("statvfs error");
    pthread_exit(NULL);
  }
  char mode_save_logfile[7];

  unsigned long total_space = (stat1.f_blocks * stat1.f_frsize);

  unsigned long used_space = (stat1.f_blocks - stat1.f_bfree) * stat1.f_frsize;
  float memory_usage = (float)used_space / total_space * 100;
  float CAPACITY = (float)total_space / (1024 * 1024 * 1024);
  float used_space_gb = (float)used_space / (1024 * 1024 * 1024);

  if (auto_delete_logs == true)
  {
    strcpy(mode_save_logfile, "Auto");
  }
  else
  {
    strcpy(mode_save_logfile, "Manual");
  }
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
  printf("\r\n\t\t | | CAPACITY: %.2f GB (100%)         |  Used space: %.2f GB (%.2f%%)        | Free space: %.2f GB (%.2f%%)                                                                                |", CAPACITY, used_space_gb, 100 - memory_usage, CAPACITY - used_space_gb, memory_usage);
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+-------------------------------------------------------------------------------------------+");
  printf("\r\n\t\t | | Current log file saving threshold: %.2f %                                                                                                                                             |", Threshold_SD);
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+------------------+------------------------------------------------------------------------+");
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+------------------+------------------------------------------------------------------------+");
  printf("\r\n\t\t | | Current log file saving mode: %s                                                                                                                                                      |", mode_save_logfile);
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+------------------+------------------------------------------------------------------------+");
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+------------------+------------------------------------------------------------------------+");
  printf("\r\n\t\t | | Time counter: %d s                                                                                                                                                                      |", Threshold_time_counter);
  printf("\r\n\t\t | +--------------+-------------+-------------+-------------+---------------------+--------------+------------------+------------------------------------------------------------------------+");
  printf("\r\n ================+===========+===============================================================================================================================================================================+");
}
// void display_log_files(const char *filename)
// {
//   char key;
//   DIR *dir;
//   struct dirent *entry;
//   int file_count = 0;

//   dir = opendir(filename);
//   if (dir == NULL)
//   {
//     perror("opendir error");
//     return;
//   }

//   printf("\r\n ================+===========================================================================================================================================================================================+");
//   printf("\r\n\t\t | List of Log File                                                                                                     |");

//   while ((entry = readdir(dir)) != NULL)
//   {
//     if (entry->d_type == DT_REG && strstr(entry->d_name, ".log") != NULL)
//     {
//       file_count++;
//       printf("\r\n\t\t |%d. %s\n", file_count, entry->d_name);
//       printf("\r\n -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
//     }
//   }
//   closedir(dir);
// }
void display_log_files(const char *dir_path)
{
  DIR *dir;
  struct dirent *entry;
  int file_count = 0;

  dir = opendir(dir_path);
  if (dir == NULL)
  {
    perror("opendir error");
    return;
  }

  printf("\r\n ================+===========================================================================================================================================================================================+");
  printf("\r\n\t\t | List of Log Files                                                                                                    |");
  printf("\r\n -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_type == DT_REG && strstr(entry->d_name, ".log") != NULL)
    {
      file_count++;

      if (file_count % 2 == 1)
      {
        printf("\r\n\t\t | %d. %-50s", file_count, entry->d_name);
      }
      else
      {
        printf(" | %d. %-50s |", file_count, entry->d_name);
        printf("\r\n -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
      }
    }
  }

  if (file_count % 2 == 1)
  {
    printf(" |\n -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
  }

  closedir(dir);
}

void delete_log_file(const char *dir_path)
{

  char key;
  int file_index;
  char file_name[256] = "";
  char file_path[256];
  printf("\r\n\t\tEnter the number: ");
  scanf("%d", &file_index);

  if (file_index < 1)
  {
    printf("\r\n\t\tThe number not valid! ");
    return;
  }

  DIR *dir = opendir(dir_path);
  if (dir == NULL)
  {
    perror("opendir error");
    return;
  }

  struct dirent *entry;
  int count = 0;
  char newest_file[256] = "";
  struct stat file_stat;
  time_t newest_time = 0;

  // find the newest file in the directory
  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_type == DT_REG && strstr(entry->d_name, ".log") != NULL)
    {
      sprintf(file_path, "%s/%s", dir_path, entry->d_name);
      if (stat(file_path, &file_stat) == 0)
      {
        if (file_stat.st_mtime > newest_time)
        {
          newest_time = file_stat.st_mtime;
          strcpy(newest_file, entry->d_name);
        }
      }
    }
  }

  rewinddir(dir); // Reset the directory stream to read it again

  //  find the file corresponding to the user input
  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_type == DT_REG && strstr(entry->d_name, ".log") != NULL)
    {
      count++;
      if (count == file_index)
      {
        strcpy(file_name, entry->d_name);
        break;
      }
    }
  }

  closedir(dir);

  if (file_name[0] == '\0')
  {
    printf("\r\n\t\tFile not found! ");
    return;
  }

  // Check if the selected file is the newest one
  if (strcmp(file_name, newest_file) == 0)
  {

    printf("\n");
    printf("\r\n    SETTING     | File %s is currently being written, if you delete it a new file will automatically be created to replace it? (Y/N):", newest_file);
    while (1)
    {
      scanf("%c", &key);
      if (key == 'y' || key == 'Y')
      {
        sprintf(file_path, "%s/%s", dir_path, file_name);
        if (unlink(file_path) != 0)
        {
          perror("remove error");
          return;
        }
        printf("\r\n\t\tFile deleted successfully!!! %s\n", file_name);

        create_new_log_file();
        sleep(2);
        break;
      }
      else if (key == 'N' || key == 'n')
      {
        break;
      }
      if (key != 'y' || key != 'Y' || key != 'n' || key != 'N')
      {
        printf("\r    SETTING     | File %s is currently being written, if you delete it a new file will automatically be created to replace it? (Y/N):", newest_file);
      }
    }
  }
  else
  {
    sprintf(file_path, "%s/%s", dir_path, file_name);
    if (unlink(file_path) != 0)
    {
      perror("remove error");
      return;
    }
    printf("\r\n\t\tFile deleted successfully!!! %s\n", file_name);
    sleep(2);
  }
}
//=========================================================
// attack
// void open_attacker_log_file()
// {
//   // Create the directory if it doesn't exist
//   struct stat st = {0};
//   if (stat(ATTACKER_LOG_DIR, &st) == -1)
//   {
//     if (mkdir(ATTACKER_LOG_DIR, 0777) != 0)
//     { // Create directory with permissions 0777 (read, write, execute for all)
//       if (errno != EEXIST)
//       {                        // Ignore error if directory already exists
//         perror("mkdir error"); // Handle the error (e.g., exit or continue without logging)
//         return;                // Or handle the error in a way that makes sense for your application
//       }
//     }
//   }
//   attacker_log_file = fopen(ATTACKER_LOG_FILE, "a");
//   if (attacker_log_file == NULL)
//   {
//     perror("fopen attacker log file error"); // Handle error appropriately
//   }
// }
// void close_attacker_log_file()
// {
//   if (attacker_log_file != NULL)
//   {
//     fclose(attacker_log_file);
//     attacker_log_file = NULL;
//   }
// }
// void log_attacker_ip(const char *src_ip)
// {
//   pthread_mutex_lock(&log_mutex); // Use the same mutex as the main log file

//   if (attacker_log_file != NULL)
//   {
//     fprintf(attacker_log_file, "%s\n", src_ip);
//     fflush(attacker_log_file); // Flush immediately for real-time logging
//   }
//   pthread_mutex_unlock(&log_mutex);
// }
//==========================================================
void read_threshold_timecounter_from_file()
{
  FILE *file = fopen(time_counter, "r");
  if (file == NULL)
  {

    file = fopen(time_counter, "w");
    if (file == NULL)
    {
      printf("Error creating config file: %s\n", time_counter);
      exit(1);
    }
    fprintf(file, "5"); //  ?t gi  tr? m?c d?nh l  true
    fclose(file);
  }
  else
  {
    if (fscanf(file, "%d", &Threshold_time_counter) != 1)
    {
      printf("\r\n\t\tCannot threshold from file\n");
      fclose(file);
      exit(1);
    }

    fclose(file);
  }
}

//
void write_threshold_time_counter_to_file()
{
  FILE *file = fopen(time_counter, "w");
  if (file == NULL)
  {
    printf("\r\n\t\tCannot open file %s\n", time_counter);
    exit(1);
  }

  fprintf(file, "%d\n", Threshold_time_counter);
  fclose(file);
}

//
void update_threshold_time_counter()
{
  int new_threshold;
  char save_choice;

  do
  {
    printf("\r\n\t\t Enter the new time counter:  ");
    scanf("%d", &new_threshold);

    if (new_threshold >= 0)
    {

      printf("\r\n\t\t Do you want to save? (y/n): ");
      scanf(" %c", &save_choice);

      if (save_choice == 'y' || save_choice == 'Y')
      {

        Threshold_time_counter = new_threshold;

        printf("\r\n\t\t Updated time counter:  %d\n", new_threshold);

        write_threshold_time_counter_to_file();
      }
      else
      {

        printf("\r\n\t\t Update time counter failed\n");
      }
    }
    else
    {

      printf("Invalid value! Please re-enter.\n");
    }
  } while (new_threshold < 0);
}

void read_threshold_from_file()
{
  FILE *file = fopen(threshold_logfile, "r");
  if (file == NULL)
  {
    // T?o file n?u file chua t?n t?i
    file = fopen(threshold_logfile, "w");
    if (file == NULL)
    {
      printf("Error creating config file: %s\n", threshold_logfile);
      exit(1);
    }
    fprintf(file, "80");
    fclose(file);
  }
  else
  {
    if (fscanf(file, "%f", &Threshold_SD) != 1)
    {
      printf("\r\n\t\tCannot open file \n");
      fclose(file);
      exit(1);
    }

    fclose(file);
  }
}

//
void write_threshold_to_file()
{
  FILE *file = fopen(threshold_logfile, "w");
  if (file == NULL)
  {
    printf("Cannot open file %s\n", threshold_logfile);
    exit(1);
  }
  fprintf(file, "%f\n", Threshold_SD);

  fclose(file);
}

//
void update_threshold_SDCard()
{
  float new_threshold;
  char save_choice;

  do
  {
    printf("\r\n\t\t Enter the new threshold value (0 -> 100): ");
    scanf("%f", &new_threshold);
    if (new_threshold >= 0 && new_threshold <= 100)
    {
      printf("\r\n\t\t Do you want to save? (Y/N): ");
      scanf(" %c", &save_choice);

      if (save_choice == 'y' || save_choice == 'Y')
      {

        Threshold_SD = new_threshold;
        printf("\r\n\t\t Threshold updated:  %f\n", new_threshold);
        write_threshold_to_file();
      }
      else
      {
        // Ngu?i d ng kh ng mu?n luu
        printf("\r\n\t\t Update logging mode failed\n");
      }
    }
    else
    {
      // N?u nh?p gi  tr? kh ng h?p l?, y u c?u nh?p l?i
      printf("Invalid value! Please re-enter.\n");
    }
  } while (new_threshold < 0 || new_threshold > 100);
}
//**************************************************//
void create_new_log_file()
{
  // char new_log_file[32];
  char new_log_file_flood[64];
  char new_log_file_normal[64];
  char current_date[11];
  get_current_date(current_date);
  time_t now = time(NULL);
  struct tm *timeinfo = localtime(&now);
  char time_str[9];
  strftime(time_str, sizeof(time_str), "%H-%M-%S", timeinfo);
  sprintf(new_log_file_flood, "%s/%s_%s.log", LOG_FLOOD_DIR, current_date, time_str);
  sprintf(new_log_file_normal, "%s/%s_%s.log", LOG_NORMAL_DIR, current_date, time_str);

  strcpy(name_logfile_flood, new_log_file_flood);
  strcpy(name_logfile_normal, new_log_file_normal);

  if (current_log_file_flood != NULL)
  {
    fclose(current_log_file_flood);
  }
  if (current_log_file_normal != NULL)
  {
    fclose(current_log_file_normal);
  }

  current_log_file_flood = fopen(new_log_file_flood, "a");
  current_log_file_normal = fopen(new_log_file_normal, "a");

  if (current_log_file_flood == NULL || current_log_file_normal == NULL)
  {
    perror("fopen error");

    return;
  }
  // open_attacker_log_file();
}

void process_packet(unsigned char *buffer, int size)
{
  struct ethhdr *eth = (struct ethhdr *)buffer;
  int header_size = sizeof(struct ethhdr);
  int payload_size = size - header_size;
  const unsigned char *payload = buffer + header_size;

  if ((memcmp(eth->h_dest, target_mac_attack, 6) == 0))
  {
    unsigned char extracted_ID[2];
    unsigned char extracted_src_ip[16];
    unsigned char extracted_dst_ip[16];
    unsigned char extracted_src_port[2];
    unsigned char extracted_dst_port[2];
    unsigned char extracted_protocol[1];
    unsigned char extracted_time[4];
    unsigned char extracted_bw[4];
    unsigned char extracted_PKT_counter[4];
    unsigned char extracted_type[1];
    unsigned char extracted_check_header[1];

    memcpy(extracted_ID, payload + 2, 2);
    memcpy(extracted_src_ip, payload + 6, 16);
    memcpy(extracted_dst_ip, payload + 22, 16);
    memcpy(extracted_src_port, payload + 38, 2);
    memcpy(extracted_dst_port, payload + 40, 2);
    memcpy(extracted_protocol, payload + 42, 1);
    memcpy(extracted_time, payload + 43, 4);
    memcpy(extracted_bw, payload + 47, 4);
    memcpy(extracted_PKT_counter, payload + 51, 4);
    memcpy(extracted_type, payload + 55, 1);
    memcpy(extracted_check_header, payload + 5, 1);

    unsigned short id_value = (extracted_ID[0] << 8) | extracted_ID[1];
    // //printf("id_value: %u\n", id_value);
    unsigned char protocol = extracted_protocol[0];
    //
    time_t rawtime = (time_t)((extracted_time[0] << 24) | (extracted_time[1] << 16) | (extracted_time[2] << 8) | (extracted_time[3]));
    struct tm *timeinfo = gmtime(&rawtime);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    //
    unsigned int bw = ntohl(*((unsigned int *)extracted_bw));
    unsigned int pkt_counter = ntohl(*((unsigned int *)extracted_PKT_counter));
    unsigned char type = extracted_type[0];
    unsigned int src_port = ntohs(*((unsigned short *)extracted_src_port));
    unsigned int dst_port = ntohs(*((unsigned short *)extracted_dst_port));

    char src_ip[42];
    char dst_ip[42];
    if ((unsigned char)extracted_check_header[0] == 0x42)
    {
      unsigned int src_ip_int = ntohl(*((unsigned int *)extracted_src_ip));
      unsigned int dst_ip_int = ntohl(*((unsigned int *)extracted_dst_ip));

      sprintf(src_ip, "%d.%d.%d.%d", extracted_src_ip[12], extracted_src_ip[13], extracted_src_ip[14], extracted_src_ip[15]);
      sprintf(dst_ip, "%d.%d.%d.%d", extracted_dst_ip[12], extracted_dst_ip[13], extracted_dst_ip[14], extracted_dst_ip[15]);
    }
    else if ((unsigned char)extracted_check_header[0] == 0x62)
    {

      sprintf(src_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", extracted_src_ip[0], extracted_src_ip[1], extracted_src_ip[2], extracted_src_ip[3],
              extracted_src_ip[4], extracted_src_ip[5], extracted_src_ip[6], extracted_src_ip[7], extracted_src_ip[8], extracted_src_ip[9], extracted_src_ip[10], extracted_src_ip[11],
              extracted_src_ip[12], extracted_src_ip[13], extracted_src_ip[14], extracted_src_ip[15]);

      sprintf(dst_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", extracted_dst_ip[0], extracted_dst_ip[1], extracted_dst_ip[2], extracted_dst_ip[3],
              extracted_dst_ip[4], extracted_dst_ip[5], extracted_dst_ip[6], extracted_dst_ip[7], extracted_dst_ip[8], extracted_dst_ip[9], extracted_dst_ip[10], extracted_dst_ip[11],
              extracted_dst_ip[12], extracted_dst_ip[13], extracted_dst_ip[14], extracted_dst_ip[15]);
    }
    char type_str[32];
    char protocol_str[32];

    //
    switch (type)
    {
    case 1:
      strcpy(type_str, "SYN Flood");
      break;
    case 2:
      strcpy(type_str, "LAND Attack");
      break;
    case 3:
      strcpy(type_str, "UDP Flood");
      break;
    case 4:
      strcpy(type_str, "DNS Flood");
      break;
    case 5:
      strcpy(type_str, "IPSec IKE Flood");
      break;
    case 6:
      strcpy(type_str, "ICMP Flood");
      break;
    case 7:
      strcpy(type_str, "TCP Fragment");
      break;
    case 8:
      strcpy(type_str, "UDP Fragment");
      break;
    case 9:
      strcpy(type_str, "DNS AUTH PKT");
      break;
    case 10:
      strcpy(type_str, "HTTP Flood");
      break;
    default:
      strcpy(type_str, "Unknown");
      break;
    }
    //
    switch (protocol)
    {
    case 6:
      strcpy(protocol_str, "TCP");
      break;
    case 17:
      strcpy(protocol_str, "UDP");
      break;
    case 1:
      strcpy(protocol_str, "ICMP");
      break;
    case 58:
      strcpy(protocol_str, "ICMP");
      break;
    default:
      strcpy(protocol_str, "Unknown");
      break;
    }

    char binary[10];
    for (int i = 0; i < 9; i++)
    {
      binary[i] = (id_value & (1 << (8 - i))) ? '1' : '0';
    }
    binary[9] = '\0';

    int result_str_size = 1;
    char *result_str = NULL;
    char *mapping[] = {" HTTP Flood ", " UDP Fragmentation attack ", " TCP Fragmentation attack ", " IPSec IKE Flood ", " ICMP Flood ", " DNS Flood ", " UDP Flood ", " LAND Attack ", " SYN Flood "};

    for (int i = 0; i < 8; i++)
    {
      if (binary[i] == '1')
      {
        result_str_size += strlen(mapping[i]) + 3;
      }
    }
    result_str = (char *)malloc(result_str_size + 32);
    if (result_str == NULL)
    {
      perror("Failed to allocate memory");
      return;
    }
    result_str[0] = '\0';
    int types_count = 0;
    for (int i = 0; i < 9; i++)
    {
      if (binary[i] == '1')
      {
        if (types_count > 0)
        {
          strcat(result_str, "+");
        }

        strcat(result_str, mapping[i]);
        types_count++;
      }
    }
    char lcd_message[result_str_size + 32];
    snprintf(lcd_message, result_str_size + 32, "%s", result_str);
    // printf("\n ss: %s", lcd_message);
    free(result_str);

    //
    pthread_mutex_lock(&lcd_queue.mutex);
    if (strcmp(lcd_message, current_attack) != 0)
    {
      strcpy(current_attack, lcd_message);
      //  pthread_mutex_lock(&lcd_queue.mutex);
      lcd_queue.front = lcd_queue.rear = 0;
      // pthread_mutex_unlock(&lcd_queue.mutex);
    }

    snprintf(lcd_queue.messages[lcd_queue.rear], result_str_size + 32, "%s", lcd_message);
    lcd_queue.rear = (lcd_queue.rear + 1) % QUEUE_SIZE;
    pthread_cond_signal(&lcd_queue.cond);
    pthread_mutex_unlock(&lcd_queue.mutex);

    if ((memcmp(extracted_time, prev_time, 4) == 0))
    {
      bw_accumulated += bw;
    }
    else
    {

      sprintf(bw1, "%d", bw_accumulated);

      bw_accumulated = bw;
      memcpy(prev_time, extracted_time, 4);
    }
    // Log to file

    // Send socket

    pthread_mutex_lock(&log_mutex);
    if (current_log_file_flood != NULL)
    {

      fprintf(current_log_file_flood, "%s  %s  %s  %u  %u  %s  %s  %u  %u\n",
              time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
      fflush(current_log_file_flood);
    }
    pthread_mutex_unlock(&log_mutex);
    // log_attacker_ip(src_ip);

    static int packet_count = 0;
    if (packet_count % SAMPLING_RATE == 0)
    {

      if ((unsigned char)extracted_check_header[0] == 0x42)
      {
        // snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
        //          " \n|  %s  |  \t\t%s\t\t    |  \t\t%s\t\t       |  %6u\t|  %6u\t|  %6s\t|  %17s    |  %8u     |  %8u     |",
        //          time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);

        snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
                 " \n|  %s  |  \t\t%s\t\t    |  \t\t%s\t\t       |  %6u\t|  %6u\t|  %6s\t|  %s%17s%s    |  %8u     |  %10u     |",
                 time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, KRED, type_str, RESET, bw, pkt_counter);
      }
      else if ((unsigned char)extracted_check_header[0] == 0x62)
      {
        snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
                 " \n|  %s  |  %s  | %s  |  %6u\t|  %6u\t|  %6s\t| %s%17s%s    |  %8u     |  %10u     |",
                 time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, KRED, type_str, RESET, bw, pkt_counter);
      }
      print_buffer_pos += strlen(print_buffer + print_buffer_pos);
    }
    packet_count++;

    if (strcmp(type_str, "HTTP Flood") == 0)
    {
      if (strlen(src_ip) > 20)
      {
        process_ip(LOGFILE_HTTP_IPv6, src_ip);
      }
      else
      {
        process_ip(LOGFILE_HTTP_IPv4, src_ip);
      }
    }
    // count++;
    count_tancong++;
  }

  else if ((memcmp(eth->h_dest, target_mac, 6) == 0))
  {

    static const unsigned char zero_array[16] = {0};

    if (memcmp(payload + 6, zero_array, 16) == 0 || memcmp(payload + 22, zero_array, 16) == 0)
    {
      return;
    }
    unsigned char extracted_ID[2];
    unsigned char extracted_src_ip[16];
    unsigned char extracted_dst_ip[16];
    unsigned char extracted_src_port[2];
    unsigned char extracted_dst_port[2];
    unsigned char extracted_protocol[1];
    unsigned char extracted_time[4];
    unsigned char extracted_bw[4];
    unsigned char extracted_PKT_counter[4];
    unsigned char extracted_type[1];
    unsigned char extracted_check_header[1];
    memcpy(extracted_ID, payload + 2, 2);
    memcpy(extracted_src_ip, payload + 6, 16);
    memcpy(extracted_dst_ip, payload + 22, 16);

    memcpy(extracted_src_port, payload + 38, 2);
    memcpy(extracted_dst_port, payload + 40, 2);
    memcpy(extracted_protocol, payload + 42, 1);
    memcpy(extracted_time, payload + 43, 4);
    memcpy(extracted_bw, payload + 47, 4);
    memcpy(extracted_PKT_counter, payload + 51, 4);
    memcpy(extracted_type, payload + 55, 1);
    memcpy(extracted_check_header, payload + 5, 1);

    unsigned char id_value = extracted_ID[1];
    unsigned char protocol = extracted_protocol[0];
    //
    time_t rawtime = (time_t)((extracted_time[0] << 24) | (extracted_time[1] << 16) | (extracted_time[2] << 8) | (extracted_time[3]));
    struct tm *timeinfo = gmtime(&rawtime);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    //
    unsigned int bw = ntohl(*((unsigned int *)extracted_bw));
    unsigned int pkt_counter = ntohl(*((unsigned int *)extracted_PKT_counter));
    unsigned char type = extracted_type[0];
    unsigned int src_port = ntohs(*((unsigned short *)extracted_src_port));
    unsigned int dst_port = ntohs(*((unsigned short *)extracted_dst_port));

    char src_ip[42];
    char dst_ip[42];

    if ((unsigned char)extracted_check_header[0] == 0x42)
    {
      unsigned int src_ip_int = ntohl(*((unsigned int *)extracted_src_ip));
      unsigned int dst_ip_int = ntohl(*((unsigned int *)extracted_dst_ip));

      sprintf(src_ip, "%d.%d.%d.%d", extracted_src_ip[12], extracted_src_ip[13], extracted_src_ip[14], extracted_src_ip[15]);
      sprintf(dst_ip, "%d.%d.%d.%d", extracted_dst_ip[12], extracted_dst_ip[13], extracted_dst_ip[14], extracted_dst_ip[15]);
    }
    else if ((unsigned char)extracted_check_header[0] == 0x62)
    {

      sprintf(src_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", extracted_src_ip[0], extracted_src_ip[1], extracted_src_ip[2], extracted_src_ip[3],
              extracted_src_ip[4], extracted_src_ip[5], extracted_src_ip[6], extracted_src_ip[7], extracted_src_ip[8], extracted_src_ip[9], extracted_src_ip[10], extracted_src_ip[11],
              extracted_src_ip[12], extracted_src_ip[13], extracted_src_ip[14], extracted_src_ip[15]);
      sprintf(dst_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", extracted_dst_ip[0], extracted_dst_ip[1], extracted_dst_ip[2], extracted_dst_ip[3],
              extracted_dst_ip[4], extracted_dst_ip[5], extracted_dst_ip[6], extracted_dst_ip[7], extracted_dst_ip[8], extracted_dst_ip[9], extracted_dst_ip[10], extracted_dst_ip[11],
              extracted_dst_ip[12], extracted_dst_ip[13], extracted_dst_ip[14], extracted_dst_ip[15]);
    }
    char type_str[32];
    char protocol_str[32];

    //
    switch (type)
    {
    case 0:
      strcpy(type_str, "Normal");
      break;

    default:
      strcpy(type_str, "Normal");
      break;
    }
    //
    switch (protocol)
    {
    case 6:
      strcpy(protocol_str, "TCP");
      break;
    case 17:
      strcpy(protocol_str, "UDP");
      break;
    case 1:
      strcpy(protocol_str, "ICMP");
      break;
    case 58:
      strcpy(protocol_str, "ICMP");
      break;
    default:
      strcpy(protocol_str, "Unknown");
      break;
    }

    pthread_mutex_lock(&log_mutex);
    if (current_log_file_normal != NULL)
    {

      fprintf(current_log_file_normal, "%s  %s  %s  %u  %u  %s  %s  %u  %u\n",
              time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
      fflush(current_log_file_normal);
    }
    pthread_mutex_unlock(&log_mutex);

    // In ra terminal n?u d p ?ng di?u ki?n sampling
    static int packet_count = 0;
    if (packet_count % SAMPLING_RATE == 0)
    {
      // printf(" \n\n|\tTime\t\t\t|\tSource IP\t\t|\tDest IP\t\t|\tSource Port\t|\tDest Port\t|\tProtocol\t|\tType\t|\tBW\t|\tPKT\t|");
      // Th m th ng tin v o b? d?m in ra terminal

      // snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
      //          " \n|\t%s\t|\t%s\t|\t%s\t|\t%u\t|\t%u\t|\t%s\t|\t%s\t\t|\t%u\t|\t%u\t|",
      //          time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);

      if ((unsigned char)extracted_check_header[0] == 0x42)
      {
        // snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
        //          " \n|  %s  |  \t\t%s\t\t    |  \t\t%s\t\t       |  %6u\t|  %6u\t|  %6s\t|  %17s    |  %8u     |  %8u     |",
        //          time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
        snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
                 " \n|  %s  |  \t\t%s\t\t    |  \t\t%s\t\t       |  %6u\t|  %6u\t|  %6s\t|  \x1B[32m%17s\x1B[0m    |  %8u     |  %10u     |",
                 time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
      }
      else if ((unsigned char)extracted_check_header[0] == 0x62)
      {
        // snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
        //          " \n|  %s  |  %s  | %s  |  %6u\t|  %6u\t|  %6s\t|  %17s    |  %8u     |  %8u     |",
        //          time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
        snprintf(print_buffer + print_buffer_pos, PRINT_BUFFER_SIZE - print_buffer_pos,
                 " \n|  %s  |  %s  | %s  |  %6u\t|  %6u\t|  %6s\t|  \x1B[32m%17s\x1B[0m    |  %8u     |  %10u     |",
                 time_str, src_ip, dst_ip, src_port, dst_port, protocol_str, type_str, bw, pkt_counter);
      }

      print_buffer_pos += strlen(print_buffer + print_buffer_pos);
    }
    packet_count++;
    // count++;
  }
}

void enqueue_packet(unsigned char *packet, int size)
{
  pthread_mutex_lock(&packet_queue.mutex);
  memcpy(packet_queue.packets[packet_queue.rear], packet, size);
  packet_queue.rear = (packet_queue.rear + 1) % PACKET_QUEUE_SIZE;
  pthread_cond_signal(&packet_queue.cond);
  pthread_mutex_unlock(&packet_queue.mutex);
}

//
void *packet_queue_processing_thread(void *arg)
{
  while (1)
  {
    pthread_mutex_lock(&packet_queue.mutex);
    while (packet_queue.front == packet_queue.rear)
    {
      pthread_cond_wait(&packet_queue.cond, &packet_queue.mutex);
    }
    unsigned char *packet = packet_queue.packets[packet_queue.front];
    int size = BUFFER_SIZE; // Assuming all packets have the same size
    packet_queue.front = (packet_queue.front + 1) % PACKET_QUEUE_SIZE;
    pthread_mutex_unlock(&packet_queue.mutex);

    // X? l  packet
    process_packet(packet, size);
  }
  return NULL;
}

void *lcd_thread_function(void *arg)
{
  while (1)
  {

    if (!is_idle2)
    {
      pthread_mutex_lock(&lcd_queue.mutex);
      // snprintf(lcd_queue.messages[lcd_queue.rear], 255, "ACRONICS SOLUTIONS");
      lcd_queue.rear = (lcd_queue.rear + 1) % QUEUE_SIZE;
      pthread_cond_signal(&lcd_queue.cond);
      pthread_mutex_unlock(&lcd_queue.mutex);
    }

    pthread_mutex_lock(&lcd_queue.mutex);

    while (lcd_queue.front == lcd_queue.rear)
    {
      pthread_cond_wait(&lcd_queue.cond, &lcd_queue.mutex);
    }

    char message[255];
    snprintf(message, 255, "%s", lcd_queue.messages[lcd_queue.front]);
    lcd_queue.front = (lcd_queue.front + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&lcd_queue.mutex);
    pthread_mutex_lock(&lcd_mutex);
    // //printf("\n aa: %s", message);
    if (show_disconnected_message)
    {
      ClrLcd();
      lcdLoc(LINE1);
      typeString("  DISCONNECTED");
    }
    else
    {
      if (is_idle)
      {
        pthread_mutex_lock(&lcd_queue.mutex);
        lcd_queue.front = lcd_queue.rear = 0;
        pthread_mutex_unlock(&lcd_queue.mutex);
        scroll_text1("ACRONICS SOLUTIONS", "ACS Sysnet-Def v1.0", 150);
      }
      else
      {
        char bw1_with_space[20];
        snprintf(bw1_with_space, sizeof(bw1_with_space), "  %s", bw1);
        scroll_text1(message, bw1_with_space, 100);
      }
    }
    pthread_mutex_unlock(&lcd_mutex);

    // memory_check_thread_function();
    usleep(200000);
  }

  return NULL;
}

void scroll_text(const char *text, int delay_ms)
{
  int len = strlen(text);
  char buffer[255] = {0};
  while (1)
  {
    for (int pos = 0; pos <= len; pos++)
    {
      ClrLcd();
      for (int i = 0; i < 16; i++)
      {
        int text_index = i + pos;
        if (text_index >= 0 && text_index < len)
        {
          buffer[i] = text[text_index];
        }
        else
        {
          buffer[i] = ' ';
        }
      }
      lcdLoc(LINE1);
      typeString(buffer);
      delay(delay_ms);
      ClrLcd();
    }
    if (stop_scrolling)
    {
      break;
    }
  }
}

void update_lcd(const char *message)
{
  ClrLcd();
  lcdLoc(LINE1);
  // lcdLoc(LINE2);
  typeString(message);
}

void get_current_date(char *date_str)
{
  time_t rawtime;
  struct tm *timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(date_str, 11, "%Y-%m-%d", timeinfo);
}

void scroll_text1(const char *text1, const char *text2, int delay_ms)
{
  int len1 = strlen(text1);
  int len2 = strlen(text2);
  char buffer1[255] = {0};
  char buffer2[255] = {0};

  while (1)
  {
    for (int pos = 0; pos <= len1; pos++)
    {
      ClrLcd();
      for (int i = 0; i < 16; i++)
      {
        int text_index = i + pos;
        if (text_index >= 0 && text_index < len1)
        {
          buffer1[i] = text1[text_index];
        }
        else
        {
          buffer1[i] = ' ';
        }
      }
      lcdLoc(LINE1);
      typeString(buffer1);

      //
      for (int i = 0; i < 16; i++)
      {
        int text_index = i + pos;
        if (text_index >= 0 && text_index < len2)
        {
          buffer2[i] = text2[text_index];
        }
        else
        {
          buffer2[i] = ' ';
        }
      }
      lcdLoc(LINE2);
      typeString(buffer2);

      delay(delay_ms);
      ClrLcd();
    }
    if (stop_scrolling)
    {
      break;
    }
  }
}

// void remove_old_logs(void)
// {
//   DIR *dir;
//   struct dirent *entry;
//   time_t now = time(NULL);
//   char file_path[512];

//   dir = opendir(LOG_FLOOD_DIR);
//   if (dir == NULL)
//   {
//     perror("opendir error");
//     return;
//   }

//   while ((entry = readdir(dir)) != NULL)
//   {
//     if (entry->d_type == DT_REG)
//     {
//       char *file_name = entry->d_name;

//       if (strstr(file_name, ".log") != NULL)
//       {
//         char file_date[11];
//         strncpy(file_date, file_name, 10);
//         file_date[10] = '\0';

//         struct tm tm = {0};
//         if (sscanf(file_date, "%4d-%2d-%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3)
//         {
//           tm.tm_year -= 1900;
//           tm.tm_mon -= 1;
//           time_t file_time = mktime(&tm);
//           double diff_days = difftime(now, file_time) / (60 * 60 * 24);

//           if (diff_days > MAX_LOG_DAYS)
//           {
//             snprintf(file_path, sizeof(file_path), "%s/%s", LOG_FLOOD_DIR, file_name);
//             if (remove(file_path) != 0)
//             {
//               perror("remove error");
//             }
//           }
//         }
//       }
//     }
//   }
//   closedir(dir);
// }
int open_and_check_dir(const char *dir_path)
{
  DIR *dir;
  struct dirent *entry;
  int is_empty = 1;

  dir = opendir(dir_path);
  if (dir == NULL)
  {
    perror("opendir error");
    return -1;
  }
  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
    {
      continue;
    }
    is_empty = 0;
    break;
  }
  closedir(dir);
  return is_empty;
}
//

void *memory_check_thread_function(void *arg)
{
  struct statvfs stat1;
  while (1)
  {
    check_connect_eth();
    if (statvfs("/", &stat1) != 0)
    {
      perror("statvfs error");
      pthread_exit(NULL);
    }

    unsigned long total_space = stat1.f_blocks * stat1.f_frsize;
    unsigned long used_space = (stat1.f_blocks - stat1.f_bfree) * stat1.f_frsize;
    float memory_usage = (float)used_space / total_space * 100;

    // IF USER >= MEMORY
    if (memory_usage >= Threshold_SD)
    {

      int check_empty_dir = open_and_check_dir(LOG_NORMAL_DIR);
      if (check_empty_dir == 1)
      {
        empty_log_normal = true;
      }
      else if (check_empty_dir == 0)
      {
        empty_log_normal = false;
      }

      if (auto_delete_logs)
      {

        pthread_mutex_lock(&log_mutex);
        if (!empty_log_normal)
        {
          DIR *dir = opendir(LOG_NORMAL_DIR);
          struct dirent *entry;
          time_t oldest_time = time(NULL);
          char oldest_file[256] = {0};
          int file_count = 0;
          while ((entry = readdir(dir)) != NULL)
          {
            if (entry->d_type == DT_REG)
            {
              file_count++;
              char file_path[256];
              sprintf(file_path, "%s/%s", LOG_NORMAL_DIR, entry->d_name);
              struct stat file_stat;
              stat(file_path, &file_stat);
              if (file_stat.st_mtime < oldest_time)
              {
                oldest_time = file_stat.st_mtime;
                strcpy(oldest_file, file_path);
              }
            }
          }
          closedir(dir);

          if (file_count > 0 && oldest_file[0] != '\0')
          {
            // printf("Deleted oldest file: %s\n", oldest_file);
            unlink(oldest_file);
          }
          else if (file_count == 0)
          {
            empty_log_normal = true;
          }
        }

        else
        {
          DIR *dir = opendir(LOG_FLOOD_DIR);
          struct dirent *entry;
          time_t oldest_time = time(NULL);
          char oldest_file[256] = {0};
          int file_count = 0;
          while ((entry = readdir(dir)) != NULL)
          {
            if (entry->d_type == DT_REG)
            {
              file_count++;
              char file_path[256];
              sprintf(file_path, "%s/%s", LOG_FLOOD_DIR, entry->d_name);
              struct stat file_stat;
              stat(file_path, &file_stat);
              if (file_stat.st_mtime < oldest_time)
              {
                oldest_time = file_stat.st_mtime;
                strcpy(oldest_file, file_path);
              }
            }
          }
          closedir(dir);

          if (file_count > 1 && oldest_file[0] != '\0')
          {
            // printf("Deleted oldest file: %s\n", oldest_file);
            unlink(oldest_file);
          }
          else if (file_count == 1)
          {

            if (current_log_file_flood != NULL)
            {
              fclose(current_log_file_flood);
              current_log_file_flood = NULL;
              close_flood_log = true;
            }

            full_sd = true;
          }
        }
        pthread_mutex_unlock(&log_mutex);
      }
      else
      {

        if (current_log_file_flood != NULL)
        {
          fclose(current_log_file_flood);
          current_log_file_flood = NULL;
        }
        if (current_log_file_normal != NULL)
        {
          fclose(current_log_file_normal);
          current_log_file_normal = NULL;
        }
        close_flood_log = true;
        close_normal_log = true;
        full_sd = true;
      }
      // stop_writing = true;
    }

    // IF USE < MEMORY
    if (memory_usage < Threshold_SD)
    {
      if (empty_log_normal)
      {
        char new_log_file1[32];
        char current_date1[11];
        get_current_date(current_date1);
        time_t now = time(NULL);
        struct tm *timeinfo = localtime(&now);
        char time_str[9];
        strftime(time_str, sizeof(time_str), "%H-%M-%S", timeinfo);
        sprintf(new_log_file1, "%s/%s_%s.log", LOG_NORMAL_DIR, current_date1, time_str);
        strcpy(name_logfile_normal, new_log_file1);
        if (current_log_file_normal != NULL)
        {
          fclose(current_log_file_normal);
        }
        current_log_file_normal = fopen(new_log_file1, "a");
        // if (current_log_file_normal == NULL)
        // {
        //   perror("fopen error");
        //   return;
        // }
        empty_log_normal = false;
        close_normal_log = false;
      }

      //     full_sd2 = false;
      if (close_flood_log)
      {
        current_log_file_flood = fopen(name_logfile_flood, "a");
        if (current_log_file_flood == NULL || current_log_file_normal == NULL)
        {
          perror("Error opening log file");
          pthread_exit(NULL);
        }
        close_flood_log = false;
      }
      if (close_normal_log)
      {
        current_log_file_normal = fopen(name_logfile_normal, "a");
        if (current_log_file_flood == NULL || current_log_file_normal == NULL)
        {
          perror("Error opening log file");
          pthread_exit(NULL);
        }
        close_normal_log = false;
      }
      full_sd = false;
      // stop_writing = false;
    }
    sleep(2);
  }
  pthread_exit(NULL);
}

// void *log_buffer_thread(void *arg)
// {
//   while (1)
//   {

//     if (log_buffer_pos >= 0)
//     { // printf("\nbye\n");
//       fwrite(log_buffer, 1, log_buffer_pos, current_log_file);
//       log_buffer_pos = 0; // Reset buffer
//     }
//     // pthread_mutex_unlock(&log_mutex);

//     sleep(1);
//   }
//   return NULL;
// }

void handle_signal(int sig)
{
  char key;
  if (sig == SIGTSTP)
  {

    printf("\nRestarting...\n");
    sleep(2);
    printf("\nRestarted!\n");
    send_reset(serial_port);
    sleep(1);
    exit(1);
  }
}

void send_reset(int serial_port)
{
  char key = 03;
  char enter = '\r';
  write(serial_port, &key, sizeof(key));
  usleep(100000);
  write(serial_port, &enter, sizeof(enter));
  usleep(1000000);
}

void get_custom_datetime(char *date_str)
{
  time_t rawtime;
  struct tm *timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(date_str, 17, "%y%m%d%H%M%S", timeinfo);
}

void send_time(int serial_port)
{
  char enter = '\r';
  char date_str[17];
  get_custom_datetime(date_str);

  int n = strlen(date_str);
  for (int i = 0; i < n; i++)
  {
    char data = date_str[i];
    send_data(serial_port, &data, sizeof(data));
    // printf("data :%c\n",data);
    usleep(500000);
  }
  write(serial_port, &enter, sizeof(enter));
}

void check_connect_eth()
{
  int sockfd;
  struct ifreq ifr;

  // while (1)
  // {
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1)
  {
    perror("socket");
    pthread_exit(NULL);
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
  {
    perror("ioctl");
    close(sockfd);
    pthread_exit(NULL);
  }
  bool connected = (ifr.ifr_flags & IFF_RUNNING) != 0;
  pthread_mutex_lock(&lcd_mutex);
  if (connected && show_disconnected_message)
  {

    show_disconnected_message = false;
  }
  else if (!connected)
  {
    show_disconnected_message = true;
  }
  pthread_mutex_unlock(&lcd_mutex);

  close(sockfd);
}

//
void previous_mode_fc()
{
  FILE *file = fopen(previous_mode, "w");
  if (file == NULL)
  {
    printf("Cannot open file %s\n", previous_mode);
    exit(1);
  }
  fprintf(file, "%c\n", '2');

  fclose(file);
}

// Creat file log save HTTP ip table
void create_http_filelog(const char *filename)
{

  struct stat buffer;
  if (stat(filename, &buffer) != 0)
  {
    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
      perror("Err create file http log");
      exit(EXIT_FAILURE);
    }
    fclose(file);
  }
  else
  {
  }
}

// Load file log to hash table
void load_ips_from_file(const char *filename)
{
  FILE *file = fopen(filename, "r");
  if (!file)
    return;

  char ip[MAX_IP_LEN];
  while (fgets(ip, sizeof(ip), file))
  {
    ip[strcspn(ip, "\n")] = '\0';
    g_hash_table_add(ip_table, g_strdup(ip));
  }
  fclose(file);
}

// Add ip to Filelog
void flush_batch_to_file(const char *filename)
{
  if (g_queue_is_empty(batch_queue))
    return;

  FILE *file = fopen(filename, "a");
  if (!file)
  {
    perror("Open file error");
    return;
  }

  while (!g_queue_is_empty(batch_queue))
  {
    char *ip = g_queue_pop_head(batch_queue);
    fprintf(file, "%s\n", ip);
    g_free(ip);
  }

  fclose(file);
}

// Check ip http
void process_ip(const char *filename, const char *ip)
{
  if (g_hash_table_size(ip_table) > MAX_IPS)
  {
    // printf("Äáº¡t giá»›i háº¡n %d IP, khÃ´ng lÆ°u thÃªm.\n", MAX_IPS);
    return;
  }
  // Check trung ip
  if (g_hash_table_contains(ip_table, ip))
  {
    return;
  }

  // add ip hash
  g_hash_table_add(ip_table, g_strdup(ip));
  g_queue_push_tail(batch_queue, g_strdup(ip));

  if (g_queue_get_length(batch_queue) >= BATCH_SIZE)
  {
    flush_batch_to_file(filename);
  }
}

// Send time sync in Core
void send_data_sync_time(int serial_port)
{
  char keyphay = ',';
  char key_enter = '\r';

  while (1)
  {
    bool flag = false;
    int i = 0;
    write(serial_port, &keyphay, sizeof(keyphay));
    usleep(10000);
    write(serial_port, &key_enter, sizeof(key_enter));
    usleep(1000000);
    send_time(serial_port);
    while (1)
    {
      char *data2 = receive_data(serial_port);
      if ((strchr(data2, 'S') != NULL))
      {
        flag = true;
        break;
      }
      i++;
      if (i == 10)
      {
        break;
      }
    }
    if (flag == true)
    {
      break;
    }
    sleep(3);
  }
}

// Send data http ip via core when start
void send_http_ipv4_start(int serial_port, const char *filename)
{
  FILE *file = fopen(filename, "r");
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  rewind(file);

  if (file_size == 0)
  {
    fclose(file);
    return;
  }

  char enter = '\r';
  char keycham = '.';

  write(serial_port, &keycham, sizeof(keycham));
  usleep(1000);
  write(serial_port, &enter, sizeof(enter));
  usleep(10000);
  send_ips_via_uart(LOGFILE_HTTP_IPv4);
  while (1)
  {
    char *data1 = receive_data(serial_port);
    printf("\nReceived message: %s\n", data1);
    if ((strchr(data1, 'Y') != NULL))
    {
      printf("\nSend HTTP_TABLE_IPV4 done\n");
      break;
    }
  }
}

// Send data http ip via core when start
void send_http_ipv6_start(int serial_port, const char *filename)
{
  FILE *file = fopen(filename, "r");
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  rewind(file);

  if (file_size == 0)
  {
    fclose(file);
    return;
  }

  char enter = '\r';
  char keynhaynguoc = '`';

  write(serial_port, &keynhaynguoc, sizeof(keynhaynguoc));
  usleep(1000);
  write(serial_port, &enter, sizeof(enter));
  usleep(10000);
  send_ips_via_uart(LOGFILE_HTTP_IPv6);
  while (1)
  {
    char *data1 = receive_data(serial_port);
    printf("\nReceived message2: %s\n", data1);
    if ((strchr(data1, 'Y') != NULL))
    {
      printf("\nSend HTTP_TABLE_IPV6 done\n");
      break;
    }
  }
}

// Process data in file, and add to buffer
void uart_send(const char *data, int serial_port)
{
  char enter = '\r';
  int n = strlen(data);
  for (int i = 0; i < n; i++)
  {
    char data1 = data[i];
    send_data(serial_port, &data1, sizeof(data1));
    usleep(100);
  }
  write(serial_port, &enter, sizeof(enter));
  printf("Sending via UART: %s\n", data);
}

// Send data http via uart
void send_ips_via_uart(const char *filename)
{
  char buffer[BUFFER_SIZE_SEND_IP_VIA_UART] = "";
  char ip[MAX_IP_LEN];

  FILE *file = fopen(filename, "r");
  if (!file)
  {
    perror("Open file error");
    return;
  }
  while (fgets(ip, sizeof(ip), file))
  {
    ip[strcspn(ip, "\n")] = '\0';
    if (strlen(buffer) + strlen(ip) + 2 > BUFFER_SIZE_SEND_IP_VIA_UART)
    {
      fprintf(stderr, "Full buffer\n");
      fclose(file);
      return;
    }
    strcat(buffer, ip);
    strcat(buffer, "$");
  }
  fclose(file);
  size_t len = strlen(buffer);
  if (len > 0 && buffer[len - 1] == '$')
  {
    buffer[len - 1] = '\0';
  }

  uart_send(buffer, serial_port);
}

// run function
void *run(void *arg)
{
  wiringPiSetup();
  lcd_init(LCD_ADDR);
  ClrLcd();
  pthread_mutex_t mutex1;

  pthread_mutex_init(&mutex1, NULL);
  pthread_mutex_init(&log_mutex, NULL);
  pthread_mutex_init(&lcd_mutex, NULL);
  pthread_mutex_init(&packet_queue.mutex, NULL);
  pthread_cond_init(&packet_queue.cond, NULL);
  packet_queue.front = packet_queue.rear = 0;
  lcd_queue.front = lcd_queue.rear = 0;
  pthread_mutex_init(&lcd_queue.mutex, NULL);
  pthread_cond_init(&lcd_queue.cond, NULL);

  // Create threads
  pthread_t lcd_thread;
  pthread_create(&lcd_thread, NULL, lcd_thread_function, NULL);

  pthread_t memory_check_thread;
  pthread_create(&memory_check_thread, NULL, memory_check_thread_function, NULL);

  pthread_t packet_queue_processing_thread_id;
  pthread_create(&packet_queue_processing_thread_id, NULL, packet_queue_processing_thread, NULL);

  // Create thread for log buffer
  // pthread_t log_buffer_thread_id;
  // pthread_create(&log_buffer_thread_id, NULL, log_buffer_thread, NULL);

  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_raw < 0)
  {
    perror("Socket Error");
    exit(1);
  }
  // Set socket to non-blocking
  int flags = fcntl(sock_raw, F_GETFL, 0);
  if (flags == -1)
  {
    perror("fcntl(F_GETFL)");
    exit(1);
  }
  if (fcntl(sock_raw, F_SETFL, flags | O_NONBLOCK) == -1)
  {
    perror("fcntl(F_SETFL)");
    exit(1);
  }
  // Configure interface in promiscuous mode
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
  if (ioctl(sock_raw, SIOCGIFFLAGS, &ifr) == -1)
  {
    perror("ioctl error");
    close(sock_raw);
    exit(1);
  }
  ifr.ifr_flags |= IFF_PROMISC;
  if (ioctl(sock_raw, SIOCSIFFLAGS, &ifr) == -1)
  {
    perror("ioctl error");
    close(sock_raw);
    exit(1);
  }
  unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
  if (buffer == NULL)
  {
    perror("Failed to allocate memory");
    exit(1);
  }
  struct sockaddr saddr;
  int saddr_len = sizeof(saddr);

  create_new_log_file();
  while (1)
  {
    int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
    if (data_size > 0)
    {
      stop_scrolling = 1;
      struct ethhdr *eth = (struct ethhdr *)buffer;
      if ((memcmp(eth->h_dest, target_mac_attack, 6) == 0))
      {
        detect_attack = true;
        is_idle2 = true;
        last_packet_time = time(NULL);
        enqueue_packet(buffer, data_size);
        count_tong++;
      }
      else if ((memcmp(eth->h_dest, target_mac, 6) == 0))
      {
        enqueue_packet(buffer, data_size);
      }
      else
      {
        is_idle2 = false;
      }
    }
    else if (data_size == -1 && errno != EAGAIN)
    {
      perror("Recvfrom Error");
      exit(1);
    }
    time_t current_time = time(NULL);
    if (current_time - last_packet_time > 2)
    {
      detect_attack = false;
      stop_scrolling = 1;
      is_idle = true;
    }
    else
    {
      is_idle = false;
    }
  }

  // Clean up resources
  close(sock_raw);
  free(buffer);
  // free(buffer_size);
  pthread_mutex_destroy(&log_mutex);
  pthread_mutex_destroy(&lcd_queue.mutex);
  pthread_cond_destroy(&lcd_queue.cond);
}

void new_menu(int serial_port)
{
start:
  system("clear");
  display_logo1();
  char key = 0;
  char enter = '\r';
  printf("\r\n *************************************************************************************************************************************************************************************************************");
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n ==> New Menu Selected                                                                                                                                                                                       |");
  printf("\r\n");
  printf(" ===============+===========+================================================================================================================================================================================+\r\n");
  printf("    DISPLAY     |           |                                                                                                                                                                                |\r\n");
  printf("\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     1.    | Setting RTC.                                                                                                                                                                   |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     2.    | Port 1 Settings                                                                                                                                                                |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | Port 2 Settings                                                                                                                                                                |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Port 3 Settings                                                                                                                                                                |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     5.    | Port 4 Settings                                                                                                                                                                |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     6.    | Port Mirroring Settings.                                                                                                                                                       |\r\n");
  printf("\t\t|           | 	->(Info: Configure port mirroring for network monitoring).                                                                                                                   |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     7.    | Setting attack detection time.                                                                                                                                                 |\r\n");
  printf("\t\t|           | 	->(Info: The default value is: 1 second).                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     8.    | Add VPN server name or address to legitimate VPN list.                                                                                                                         |\r\n");
  printf("\t\t|     9.    | Remove the VPN server name or address from the legal VPN list.                                                                                                                 |\r\n");
  printf("\t\t|     A.    | Add VPN server name or address IPv6 to legitimate VPN list.                                                                                                                    |\r\n");
  printf("\t\t|     B.    | Remove the VPN server name or address IPv6 from the legal VPN list.                                                                                                            |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     Z.    | Exit.                                                                                                                                                                          |\r\n");
  printf("----------------+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("    SETTING     | Your choice: ");

  while (1)
  {
    scanf("%c", &key);
    if (key == '1' || key == '2' || key == '3' || key == '4' || key == '5' || key == '6' || key == '7' ||
        key == 'L' || key == 'l' || key == 'M' || key == 'm' || key == 'S' || key == 's' || key == 'T' ||
        key == 't' || key == 'Z' || key == 'z')
    {
      break;
    }
    if (key != '1' && key != '2' && key != '3' && key != '4' && key != '5' && key != '6' && key != '7' &&
        key != 'L' && key != 'l' && key != 'M' && key != 'm' && key != 'S' && key != 's' && key != 'T' &&
        key != 't' && key != 'Z' && key != 'z')
    {
      printf("\r     SETTING    | --> Your choice: ");
    }
  }

  usleep(500000);
  if (key == '1')
  {
    system("clear");
    display_logo1();
    SetDateTime(serial_port);
    goto start;
  }
  else if (key == '2')
  {
    current_port = 1;
    system("clear");
    display_logo1();
    printf("\r\n ==> Port 1 Configuration\n");
    reconfig(serial_port);
    goto start;
  }
  else if (key == '3')
  {
    current_port = 2;
    system("clear");
    ;
    printf("\r\n ==> Port 2 Configuration\n");
    reconfig(serial_port);
    goto start;
  }
  else if (key == '4')
  {
    current_port = 3;
    system("clear");

    printf("\r\n ==> Port 3 Configuration\n");
    reconfig(serial_port);
    goto start;
  }
  else if (key == '5')
  {
    current_port = 4;
    display_logo1();
    printf("\r\n ==> Port 4 Configuration\n");
    reconfig(serial_port);
    goto start;
  }
  else if (key == '6')
  {
    system("clear");
    display_logo1();
    port_mirroring_menu(serial_port);
    goto start;
  }
  else if (key == '7')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    SetTimeflood(serial_port);
    goto start;
  }
  else if (key == '8')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    AddIPv4VPN(serial_port);
    goto start;
  }
  else if (key == '9')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    RemoveIPv4VPN(serial_port);
    goto start;
  }
  else if (key == 'A' || key == 'a')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    AddIPv6VPN(serial_port);
    goto start;
  }
  else if (key == 'B' || key == 'b')
  {
    system("clear");
    display_logo1();
    display_table(serial_port);
    RemoveIPv6VPN(serial_port);
    goto start;
  }
  else if (key == 'Z' || key == 'z')
  {
    system("clear");
    display_logo1();
    ReturnMode2(serial_port);
  }
}
void wrap_field(const char *prefix, const char *content, int width)
{
  int len = strlen(content);
  int i = 0;
  while (i < len)
  {
    printf("%s%-*.*s\n", prefix, width, width, content + i);
    i += width;
  }
}

// Hàm tách chỉ các giá trị từ chuỗi JSON kiểu đơn giản
void extract_json_values(const char *json, char *out, int out_size)
{
  int len = strlen(json);
  int out_idx = 0;
  int in_quotes = 0;
  int is_key = 1;

  for (int i = 0; i < len && out_idx < out_size - 1; i++)
  {
    if (json[i] == '"')
    {
      in_quotes = !in_quotes;
      continue;
    }

    if (in_quotes && !is_key)
    {
      out[out_idx++] = json[i];
    }

    if (!in_quotes && json[i] == ':')
    {
      is_key = 0;
    }

    if (!in_quotes && json[i] == ',')
    {
      out[out_idx++] = ',';
      out[out_idx++] = ' ';
      is_key = 1;
    }

    if (!in_quotes && json[i] == '}')
    {
      break;
    }
  }

  out[out_idx] = '\0';
}

void clean_json_array_string(const char *input, char *output, int out_size)
{
  int out_idx = 0;
  for (int i = 0; input[i] != '\0' && out_idx < out_size - 1; i++)
  {
    char c = input[i];
    if (c == '[' || c == ']' || c == '"')
      continue;
    output[out_idx++] = c;
  }
  output[out_idx] = '\0';
}

//void display_port_mirroring_config_from_db(int serial_port)
void display_port_mirroring_config_from_db(int serial_port, int show_prompt)
{ 
  int idx = 1;
  int max_width_type = 50;
  int max_width_value = 62;
  int type_len = strlen(cleaned_type);
  int value_len = strlen(extracted_values);
  int line = 1;
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int rc = sqlite3_open(DB_PATH, &db);
  sqlite3_busy_timeout(db, 2000); 
  if (rc)
  {
    printf("\n cannot open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  const char *sql =
      "SELECT di.InterfaceId, di.InterfaceIsMirroring, di.InterfaceName, "
      "mi.InterfaceName AS MonitorInterfaceName, "
      "di.InterfaceMirrorSetting, di.MirrorType, di.Value "
      "FROM DeviceInterfaces di "
      "LEFT JOIN DeviceInterfaces mi ON di.InterfaceToMonitorInterfaceId = mi.InterfaceId";

  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK)
  {
    printf("\nLỗi truy vấn: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }

  printf("\n=============================================================================================================================================================================================================+\n");
  printf("| %-3s | %-15s | %-10s | %-22s | %-22s | %-50s | %-62s |\n",
         "No", "InterfaceName", "Mirroring", "Monitor Interface ID", "MirrorSetting", "MirrorType", "Value");
  printf("|=====|=================|============|========================|========================|====================================================|================================================================|\n");
  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    int mirroring = sqlite3_column_int(stmt, 1);
    const unsigned char *interface_name = sqlite3_column_text(stmt, 2);
    const unsigned char *monitor_name = sqlite3_column_text(stmt, 3);
    const unsigned char *setting = sqlite3_column_text(stmt, 4);
    const unsigned char *type = sqlite3_column_text(stmt, 5);
    const unsigned char *value = sqlite3_column_text(stmt, 6);

    const char *mirroring_str = mirroring ? "Active" : "Inactive";
    const char *interface_name_str = interface_name ? (const char *)interface_name : "";
    const char *monitor_name_str = monitor_name ? (const char *)monitor_name : "N/A";
    const char *setting_str = setting ? (const char *)setting : "";
    char cleaned_type[512] = "";
    if (type)
      clean_json_array_string((const char *)type, cleaned_type, sizeof(cleaned_type));
    else
      strcpy(cleaned_type, "");

    const char *value_str = value ? (const char *)value : "";
    char extracted_values[512] = "";
    if (value_str && strlen(value_str) > 0)
    extract_json_values(value_str, extracted_values, sizeof(extracted_values));
    printf("| %-3d | %-15s | %-10s | %-22s | %-22s |", idx++, interface_name_str, mirroring_str, monitor_name_str, setting_str);

    // In phần đầu tiên của MirrorType
    printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type);

    printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values);

    // In phần tiếp theo nếu MirrorType hoặc Value dài
    while (line * max_width_type < type_len || line * max_width_value < value_len)
    {
      printf("| %-3s | %-15s | %-10s | %-22s | %-22s |", "", "", "", "", "");

      if (line * max_width_type < type_len)
        printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type + line * max_width_type);
      else
        printf(" %-*s |", max_width_type, "");

      if (line * max_width_value < value_len)
        printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values + line * max_width_value);
      else
        printf(" %-*s |\n", max_width_value, "");

      line++;
    }
    printf("|-----+-----------------+------------+------------------------+------------------------+----------------------------------------------------+----------------------------------------------------------------|\n");
  }
  //printf("Press Enter to return to menu...\n");
  
  if (show_prompt)
  {
    printf("Press Enter to return to menu...");
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

void Update_port_mirroring(int serial_port)
{
  char port_name[32];
  system("clear");
  display_logo1();
  printf("\nCurrent Port Mirroring Configurations:\n");
  display_port_mirroring_config_from_db(serial_port, 0);


  printf("\nEnter InterfaceName to update (e.g. eth1) or press 'exit' return previous menu :");
  scanf("%31s", port_name);
  if (strcmp(port_name, "eth5") == 0) {
  printf("Interface 'eth5' is not allowed to be selected for update.\n");
  printf("Press Enter to return to the previous menu...");
  getchar(); // Để đọc dấu Enter còn lại trong buffer
  getchar();
  system("clear");
  display_logo1();
  port_mirroring_menu(serial_port); // Quay lại menu chính hoặc menu port mirroring
  return;
}

  // Nếu người dùng nhập 'exit' thì quay về menu chính
if (strcmp(port_name, "exit") == 0)
{
  printf("Returning to main menu...\n");
  getchar(); // Clear buffer sau scanf
  system("clear");
  display_logo1();
  port_mirroring_menu(serial_port);
}
  // Kiểm tra port có tồn tại không
  sqlite3 *db;
  int rc = sqlite3_open(DB_PATH, &db);
  sqlite3_busy_timeout(db, 2000); 
  if (rc)
  {
    printf("Cannot open database: %s\n", sqlite3_errmsg(db));
    return;
  }
  const char *sql = "SELECT InterfaceIsMirroring, InterfaceMirrorSetting, MirrorType, Value FROM DeviceInterfaces WHERE InterfaceName=? AND InterfaceIsMirroring=1";
  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK)
  {
    printf("SQL error: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }
  sqlite3_bind_text(stmt, 1, port_name, -1, SQLITE_STATIC);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW)
  {
    system("clear");
    printf("No mirroring configuration found for interface '%s'.\n", port_name);
    printf("You must add a mirroring configuration before updating.\n");
    printf("No configuration found for %s.\n", port_name);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("Press Enter to return to menu...");
    getchar();
    getchar();
    system("clear");
    display_logo1();
    return;
  }

  // Lấy dữ liệu cũ
  PortMirroringConfig cfg = {0};
  strcpy(cfg.interface_name, port_name);
  cfg.is_mirroring = sqlite3_column_int(stmt, 0);
  const unsigned char *mirror_setting = sqlite3_column_text(stmt, 1);
  const unsigned char *mirror_type = sqlite3_column_text(stmt, 2);
  const unsigned char *value = sqlite3_column_text(stmt, 3);
  if (mirror_setting)
    strcpy(cfg.mirror_setting, (const char *)mirror_setting);
  if (mirror_type)
    strcpy(cfg.mirror_type, (const char *)mirror_type);
  if (value)
    strcpy(cfg.value, (const char *)value);

  sqlite3_finalize(stmt);
  sqlite3_close(db);

  printf("\nUpdating configuration for %s...\n", port_name);

  // Parse value JSON cũ thành map key-value để cập nhật lại giá trị mới nhất
  cJSON *json_old = NULL;
  if (cfg.value[0])
  {
    json_old = cJSON_Parse(cfg.value);
  }
  // Tạo struct lưu giá trị cuối cùng cho từng trường
  char last_dest_mac[18] = "";
  char last_src_mac[18] = "";
  char last_dest_ip[40] = "";
  char last_src_ip[40] = "";
  char last_dest_port[6] = "";
  char last_src_port[6] = "";
  char last_protocol[16] = "";

  if (json_old)
  {
    cJSON *item;
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "DestMac")) && cJSON_IsString(item))
      strncpy(last_dest_mac, item->valuestring, sizeof(last_dest_mac));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "SourceMac")) && cJSON_IsString(item))
      strncpy(last_src_mac, item->valuestring, sizeof(last_src_mac));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "DestIPv4")) && cJSON_IsString(item))
      strncpy(last_dest_ip, item->valuestring, sizeof(last_dest_ip));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "SourceIPv4")) && cJSON_IsString(item))
      strncpy(last_src_ip, item->valuestring, sizeof(last_src_ip));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "DestIPv6")) && cJSON_IsString(item) && strlen(item->valuestring) > 0)
      strncpy(last_dest_ip, item->valuestring, sizeof(last_dest_ip));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "SourceIPv6")) && cJSON_IsString(item) && strlen(item->valuestring) > 0)
      strncpy(last_src_ip, item->valuestring, sizeof(last_src_ip));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "DestPort")) && cJSON_IsString(item))
      strncpy(last_dest_port, item->valuestring, sizeof(last_dest_port));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "SourcePort")) && cJSON_IsString(item))
      strncpy(last_src_port, item->valuestring, sizeof(last_src_port));
    if ((item = cJSON_GetObjectItemCaseSensitive(json_old, "Protocol")) && cJSON_IsString(item))
      strncpy(last_protocol, item->valuestring, sizeof(last_protocol));
    cJSON_Delete(json_old);
  }

  // Truyền giá trị cũ vào để ConfigTypePacket cho phép sửa hoặc bổ sung
  PortMirroringConfig cfg_update = cfg;
  // Gán lại các trường đã có vào biến tạm để khi vào ConfigTypePacket sẽ hiển thị đúng
  strcpy(cfg_update.value, cfg.value);
  strcpy(cfg_update.mirror_type, cfg.mirror_type);
  //ConfigTypePacket(serial_port, &cfg_update);
  system("clear");
  display_logo1();
  Select_traffic_mirroring_mode(serial_port, &cfg_update);


  // Sau khi cấu hình xong, parse lại value mới để lấy giá trị mới nhất
  cJSON *json_new = NULL;
  if (cfg_update.value[0])
  {
    json_new = cJSON_Parse(cfg_update.value);
  }
  // Nếu trường nào không có trong value mới thì giữ lại giá trị cũ
  if (json_new)
  {
    cJSON *item;
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "DestMac")) && last_dest_mac[0])
      cJSON_AddStringToObject(json_new, "DestMac", last_dest_mac);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "SourceMac")) && last_src_mac[0])
      cJSON_AddStringToObject(json_new, "SourceMac", last_src_mac);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "DestIPv4")) && last_dest_ip[0])
      cJSON_AddStringToObject(json_new, "DestIPv4", last_dest_ip);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "SourceIPv4")) && last_src_ip[0])
      cJSON_AddStringToObject(json_new, "SourceIPv4", last_src_ip);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "DestPort")) && last_dest_port[0])
      cJSON_AddStringToObject(json_new, "DestPort", last_dest_port);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "SourcePort")) && last_src_port[0])
      cJSON_AddStringToObject(json_new, "SourcePort", last_src_port);
    if (!(item = cJSON_GetObjectItemCaseSensitive(json_new, "Protocol")) && last_protocol[0])
      cJSON_AddStringToObject(json_new, "Protocol", last_protocol);

    // Ghi lại value mới đã merge đủ các trường
    char *new_value_str = cJSON_PrintUnformatted(json_new);
    strncpy(cfg_update.value, new_value_str, sizeof(cfg_update.value) - 1);
    free(new_value_str);
    cJSON_Delete(json_new);
  }
  // Lưu lại vào DB
  save_port_mirroring_to_db(&cfg_update);
  getchar();
  getchar();
  system("clear");
  display_logo1();
}

void port_mirroring_menu(int serial_port)
{
start:
  char key = 0;
  printf("\r\n *************************************************************************************************************************************************************************************************************");
  printf("\r\n");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n ==> Port Mirroring Settings                                                                                                                                                                                 |");
  printf("\r\n");
  printf(" ===============+===========+================================================================================================================================================================================+\r\n");
  printf("    DISPLAY     |           |                                                                                                                                                                                |\r\n");
  printf("\t\t| Key Enter | Please choose 1 option below:                                                                                                                                                  |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     1.    | Display Port Mirroring Configuration.                                                                                                                                          |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     2.    | Add Port Mirroring Configuration.                                                                                                                                              |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | Update Port Mirroring.                                                                                                                                                         |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Delete Port Mirroring Configuration.                                                                                                                                           |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     5.    | Back to Previous Menu.                                                                                                                                                         |\r\n");
  printf("----------------+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("    SETTING     | Your choice: ");

  while (1)
  {
    scanf("%c", &key);
    if (key == '1' || key == '2' || key == '3' || key == '4' || key == '5')
    {
      break;
    }
    if (key != '1' && key != '2' && key != '3' && key != '4' && key != '5')
    {
      printf("\r     SETTING    | --> Your choice: ");
    }
  }

  usleep(500000);
  if (key == '1')
  {
    system("clear");
    display_logo1();
    display_port_mirroring_config_from_db(serial_port, 1);
    getchar();
    getchar();
    system("clear");
    display_logo1();
    goto start;
  }
  else if (key == '2')
  {
    system("clear");
    display_logo1();
    Add_port_mirroring(serial_port);
    printf("\nAdding Port Mirroring Configuration...\n");
    goto start;
  }
  else if (key == '3')
  {
    system("clear");
    display_logo1();
    Update_port_mirroring(serial_port);
    printf("\nDeleting Port Mirroring Configuration...\n");
    goto start;
  }
  else if (key == '4')
  {
    system("clear");
    display_logo1();
    Delete_port_mirroring(serial_port);
    goto start;
  }
  else if (key == '5')
  {
    system("clear");
    // display_logo1();
    new_menu(serial_port);
  }
}
void Delete_port_mirroring(int serial_port)
{
  while (1)
  {
    system("clear");
    display_logo1();
    printf("\nCurrent Port Mirroring Configurations:\n");
    display_port_mirroring_config_from_db(serial_port, 0);

    char port_name[32];
    printf("\nEnter InterfaceName to delete mirroring config (e.g. eth1), or type 'exit' to return: ");
    scanf("%31s", port_name);
    getchar(); // Clear newline kh?i stdin

    if (strcmp(port_name, "exit") == 0)
    {
      printf("Returning to main menu...\n");
      system("clear");
      display_logo1();
      return;
    }

    sqlite3 *db;
    int rc = sqlite3_open(DB_PATH, &db);
    sqlite3_busy_timeout(db, 2000); 
    if (rc)
    {
      printf("Cannot open database: %s\n", sqlite3_errmsg(db));
      return;
    }

    const char *update_sql =
        "UPDATE DeviceInterfaces SET "
        "InterfaceIsMirroring=0, InterfaceToMonitorInterfaceId=NULL, InterfaceMirrorSetting=NULL, MirrorType=NULL, Value=NULL "
        "WHERE InterfaceName=?";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
      printf("SQL error: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return;
    }

    sqlite3_bind_text(stmt, 1, port_name, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_DONE && sqlite3_changes(db) > 0)
    {
      printf("Deleted mirroring configuration for %s successfully!\n", port_name);
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      break;  
    }
    else
    {
      printf("No mirroring configuration found for %s or failed to delete.\n", port_name);
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      printf("Please try again or type 'exit' to return.\n");
      getchar();  
    }
  }
  printf("Press Enter to return to menu...");
  getchar(); 
  system("clear");
  display_logo1();
  port_mirroring_menu(serial_port);
}

void Add_port_mirroring(int serial_port)
{
  system("clear");
  display_logo1();
  PortMirroringConfig cfg = {0};
  cfg.is_mirroring = 1;
  int choice = 0;

  int valid_ports[] = {1, 2, 3, 4, 6, 7, 8};
  int num_ports = sizeof(valid_ports) / sizeof(valid_ports[0]);

  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n   CONFIGURE    |           |                                                                                                                                                                                |\r\n");
  printf("=============================================================================================================================================================================================================+\r\n");
  printf("\t\t| Key Enter | MONITORED PORT SELECTION                                                                                                                                                       |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");

  for (int i = 0; i < num_ports; i++)
  {
    printf("\t\t|     %d.    | eth%d                                                                                                                                                                           |\r\n", i + 1, valid_ports[i]);
    printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  }

  printf("\t\t|     %d.    | Exit.                                                                                                                                                                          |\r\n", num_ports + 1);
  printf(" ===============+=============================================================================================================================================================================================+\r\n");
  printf("\nSETTING       |  Enter your choice [1-%d]: ", num_ports + 1);
  // Đọc lựa chọn từ người dùng

  if (scanf("%d", &choice) != 1)
  {
    printf("\nInvalid input! Please enter a number between 1 and %d.\n", num_ports + 1);
    while (getchar() != '\n')
      ;
    Add_port_mirroring(serial_port);
    return;
  }

  if (choice == num_ports + 1)
  {
    system("clear");
    display_logo1();
    port_mirroring_menu(serial_port);
    return;
  }

  if (choice < 1 || choice > num_ports)
  {
    printf("\nChoice out of valid range! Please try again.\n");
    Add_port_mirroring(serial_port);
    return;
  }

  int selected_port = valid_ports[choice - 1];
  sprintf(cfg.interface_name, "eth%d", selected_port);
  cfg.monitor_target_id = -1;

  printf("\nYou selected interface: %s\n", cfg.interface_name);

  system("clear");
  display_logo1();
  Select_traffic_mirroring_mode(serial_port, &cfg);
}

void Select_traffic_mirroring_mode(int serial_port, PortMirroringConfig *cfg)
{

  char mode = 0;
  printf("\r\n ============================================================================================================================================================================================================+\r\n");
  printf("\r\n                   TRAFFIC MIRRORING MODE SETTINGS                                                                                                                                                           |");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n TRAFFIC MODE   |           |                                                                                                                                                                                |");
  printf("\r\n ===============+===========+================================================================================================================================================================================+\r\n");
  printf("\t\t|     1.    | INGRESS.                                                                                                                                                                       |\r\n");
  printf("\t\t ---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     2.    | EGRESS.                                                                                                                                                                        |\r\n");
  printf("\t\t ---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | INGRESS & EGRESS.                                                                                                                                                              |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Exit.                                                                                                                                                                          |\r\n");
  printf("\t\t =====================+======================================================================================================================================================================+\r\n");
  printf("\t\t|  SETTING  | Enter your choice [1/2/3]: ");

  scanf(" %c", &mode);

  switch (mode)
  {
  case '1':
    strcpy(cfg->mirror_setting, "Ingress");
    break;
  case '2':
    strcpy(cfg->mirror_setting, "Egress");
    break;
  case '3':
    strcpy(cfg->mirror_setting, "Ingress and Egress");
    break;
  case '4':
    system("clear");
    Add_port_mirroring(serial_port);
    return;
  default:
    printf("\nInvalid mode selected!\n");
    return;
  }
  system("clear");
  ConfigTypePacket(serial_port, cfg);
}
// Hàm tiện ích: Xóa trường khỏi mảng nếu đã tồn tại
void remove_field(char type_fields[][32], char value_fields[][40], int *field_count, const char *field_name)
{
  for (int i = 0; i < *field_count; ++i)
  {
    if (strcmp(type_fields[i], field_name) == 0)
    {
      // Dịch các phần tử sau lên
      for (int j = i; j < *field_count - 1; ++j)
      {
        strcpy(type_fields[j], type_fields[j + 1]);
        strcpy(value_fields[j], value_fields[j + 1]);
      }
      (*field_count)--;
      break;
    }
  }
}

void ConfigTypePacket(int serial_port, PortMirroringConfig *cfg)
{
  cfg->monitor_target_id = 5;

  char dest_mac[18] = "";
  char src_mac[18] = "";
  char dest_ip[40] = "";
  char src_ip[40] = "";
  char dest_port[6] = "";
  char src_port[6] = "";
  int protocol = -1;
  int flag_dest_mac = 0, flag_src_mac = 0, flag_dest_ip = 0;
  int flag_src_ip = 0, flag_dest_port = 0, flag_src_port = 0;
  int flag_protocol = 0;
  char choice;

  char mirror_type[128] = "";
  char value[256] = "";

  system("clear");
  display_logo1();
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n ==> Packet Filtering Configuration Menu                                                                                                                                                                     |");
  printf("\r\n ============================================================================================================================================================================================================+");
  printf("\r\n    DISPLAY     |           |                                                                                                                                                                                |");
  printf("\r\n ===============+===========+================================================================================================================================================================================+\r\n");
  printf("\t\t|     1.    | Destination MAC.                                                                                                                                                               |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     2.    | Source MAC.                                                                                                                                                                    |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     3.    | Destination IP.                                                                                                                                                                |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     4.    | Source IP.                                                                                                                                                                     |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     5.    | Destination Port.                                                                                                                                                              |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     6.    |  Source Port.                                                                                                                                                                  |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     7.    | Protocol.                                                                                                                                                                      |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     8.    | Save.                                                                                                                                                                          |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");
  printf("\t\t|     9.    | Exit.                                                                                                                                                                          |\r\n");
  printf("\t\t+-----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\r\n");

  char type_fields[7][32] = {0};
  char value_fields[7][40] = {0};
  int field_count = 0;
  if (cfg->mirror_type[0] && cfg->value[0])
  {
    char type_buf[128];
    strncpy(type_buf, cfg->mirror_type, sizeof(type_buf));
    char *p = type_buf;
    while (*p)
    {
      if (*p == '[' || *p == ']' || *p == '"')
        *p = ' ';
      p++;
    }
    char *type_token = strtok(type_buf, ",");
    cJSON *json = cJSON_Parse(cfg->value);
    while (type_token && field_count < 7)
    {
      while (*type_token == ' ')
        type_token++;
      char *end = type_token + strlen(type_token) - 1;
      while (end > type_token && *end == ' ')
      {
        *end = 0;
        end--;
      }
      strncpy(type_fields[field_count], type_token, sizeof(type_fields[field_count]));

      char key[32] = "";
      if (strcmp(type_token, "Dest Mac") == 0)
        strcpy(key, "DestMac");
      else if (strcmp(type_token, "Source Mac") == 0)
        strcpy(key, "SourceMac");
      else if (strcmp(type_token, "Dest IP") == 0)
        strcpy(key, "DestIPv4");
      else if (strcmp(type_token, "Source IP") == 0)
        strcpy(key, "SourceIPv4");
      else if (strcmp(type_token, "Dest Port") == 0)
        strcpy(key, "DestPort");
      else if (strcmp(type_token, "Source Port") == 0)
        strcpy(key, "SourcePort");
      else if (strcmp(type_token, "Protocol") == 0)
        strcpy(key, "Protocol");
      else
        strncpy(key, type_token, sizeof(key) - 1);

      cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
      if (item && cJSON_IsString(item))
      {
        strncpy(value_fields[field_count], item->valuestring, sizeof(value_fields[field_count]));
      }
      else
      {
        value_fields[field_count][0] = '\0';
      }
      field_count++;
      type_token = strtok(NULL, ",");
    }
    cJSON_Delete(json);
  }

  while (1)
  {
    printf("+-----------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");
    if (flag_dest_mac)
      printf("| - Destination MAC     |  %s\n", dest_mac);
    if (flag_src_mac)
      printf("| - Source MAC          |  %s\n", src_mac);
    if (flag_dest_ip)
      printf("| - Destination IP      |  %s\n", dest_ip);
    if (flag_src_ip)
      printf("| - Source IP           |  %s\n", src_ip);
    if (flag_dest_port)
      printf("| - Destination Port    |  %s\n", dest_port);
    if (flag_src_port)
      printf("| - Source Port         |  %s\n", src_port);
    if (flag_protocol)
      printf("| - Protocol            |  %d\n", protocol);
    printf("+-----------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+\n");

    printf("Your choice: ");
    scanf(" %c", &choice);

    if (choice == '1')
    {
      InputDestMAC(dest_mac);
      if (strlen(dest_mac) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Dest Mac");
        strcpy(type_fields[field_count], "Dest Mac");
        strcpy(value_fields[field_count], dest_mac);
        field_count++;
        flag_dest_mac = 1;
      }
      getchar();
    }
    else if (choice == '2')
    {
      InputSourceMAC(src_mac);
      if (strlen(src_mac) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Source Mac");
        strcpy(type_fields[field_count], "Source Mac");
        strcpy(value_fields[field_count], src_mac);
        field_count++;
        flag_src_mac = 1;
      }
      getchar();
    }
    else if (choice == '3')
    {
      InputDestIP(dest_ip);
      if (strlen(dest_ip) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Dest IP");
        strcpy(type_fields[field_count], "Dest IP");
        strcpy(value_fields[field_count], dest_ip);
        field_count++;
        flag_dest_ip = 1;
      }
      getchar();
    }
    else if (choice == '4')
    {
      InputSourceIP(src_ip);
      if (strlen(src_ip) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Source IP");
        strcpy(type_fields[field_count], "Source IP");
        strcpy(value_fields[field_count], src_ip);
        field_count++;
        flag_src_ip = 1;
      }
      getchar();
    }
    else if (choice == '5')
    {
      InputDestPort(dest_port);
      if (strlen(dest_port) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Dest Port");
        strcpy(type_fields[field_count], "Dest Port");
        strcpy(value_fields[field_count], dest_port);
        field_count++;
        flag_dest_port = 1;
      }
      getchar();
    }
    else if (choice == '6')
    {
      InputSourcePort(src_port);
      if (strlen(src_port) > 0)
      {
        remove_field(type_fields, value_fields, &field_count, "Source Port");
        strcpy(type_fields[field_count], "Source Port");
        strcpy(value_fields[field_count], src_port);
        field_count++;
        flag_src_port = 1;
      }
      getchar();
    }
    else if (choice == '7')
    {
      char protocol_str[16] = "";
      InputProtocol(&protocol, protocol_str);
      remove_field(type_fields, value_fields, &field_count, "Protocol");
      strcpy(type_fields[field_count], "Protocol");
      strcpy(value_fields[field_count], protocol_str);
      field_count++;
      flag_protocol = 1;
      getchar();
    }
    else if (choice == '8')
    {
      mirror_type[0] = '\0';
      value[0] = '\0';

      strcat(mirror_type, "[");
      strcat(value, "{");

      for (int i = 0; i < field_count; ++i)
      {
        strcat(mirror_type, "\"");
        strcat(mirror_type, type_fields[i]);
        strcat(mirror_type, "\"");
        if (i < field_count - 1)
          strcat(mirror_type, ",");

        char key[32] = {0};
        if (strcmp(type_fields[i], "Dest Mac") == 0)
          strcpy(key, "DestMac");
        else if (strcmp(type_fields[i], "Source Mac") == 0)
          strcpy(key, "SourceMac");
        else if (strcmp(type_fields[i], "Dest IP") == 0)
          strcpy(key, strchr(value_fields[i], ':') ? "DestIPv6" : "DestIPv4");
        else if (strcmp(type_fields[i], "Source IP") == 0)
          strcpy(key, strchr(value_fields[i], ':') ? "SourceIPv6" : "SourceIPv4");
        else if (strcmp(type_fields[i], "Dest Port") == 0)
          strcpy(key, "DestPort");
        else if (strcmp(type_fields[i], "Source Port") == 0)
          strcpy(key, "SourcePort");
        else if (strcmp(type_fields[i], "Protocol") == 0)
          strcpy(key, "Protocol");
        else
          strcpy(key, type_fields[i]);

        strcat(value, "\"");
        strcat(value, key);
        strcat(value, "\":\"");
        strcat(value, value_fields[i]);
        strcat(value, "\"");
        if (i < field_count - 1)
          strcat(value, ",");
      }

      strcat(mirror_type, "]");
      strcat(value, "}");

      strcpy(cfg->mirror_type, mirror_type);
      strcpy(cfg->value, value);

      system("clear");
      display_logo1();
      printf("\n+--------------------------------------------------------------+\n");
      printf("|  Saving Packet Filtering Configuration...                   |\n");
      printf("+--------------------------------------------------------------+\n");
      save_port_mirroring_to_db(cfg);
      break;
    }
    else if (choice == '9')
    {
      system("clear");
      display_logo1();
      Select_traffic_mirroring_mode(serial_port, cfg);

      //printf("\nExiting Packet Filtering Configuration...\n");

      return;
    }
    else
    {
      printf("Invalid selection! Please try again.\n");
    }
  }

  system("clear");
  new_menu(serial_port);
}

void InputDestMAC(char *mac)
{
  printf("Enter Destination MAC (format XX:XX:XX:XX:XX:XX): ");
  scanf("%17s", mac);
  while (!is_valid_mac_address(mac))
  {
    printf("Invalid MAC address! Please re-enter: ");
    scanf("%17s", mac);
  }
}

void InputSourceIP(char *ip)
{
  struct in6_addr addr6;
  int valid = 0;
  while (!valid)
  {
    printf("Enter Source IP (IPv4 or IPv6): ");
    scanf("%39s", ip);
    // Check IPv4 or IPv6 validity
    if (validate_ip_address(ip) || (inet_pton(AF_INET6, ip, &addr6) == 1))
    {
      valid = 1;
    }
    else
    {
      printf("Invalid IP address. Please re-enter:\n");
    }
  }
}

void InputSourceMAC(char *mac)
{
  printf("Enter Source MAC (format XX:XX:XX:XX:XX:XX): ");
  scanf("%17s", mac);
  while (!is_valid_mac_address(mac))
  {
    printf("Invalid MAC address! Please re-enter: ");
    scanf("%17s", mac);
  }
}
void InputDestPort(char *port)
{
  printf("Enter Destination Port: ");
  scanf("%5s", port);
}
void InputSourcePort(char *port)
{
  printf("Enter Destination Port: ");
  scanf("%5s", port);
}
void InputDestIP(char *ip)
{
  struct in6_addr addr6;
  int valid = 0;
  while (!valid)
  {
    printf("Enter Destination IP (IPv4 or IPv6): ");
    scanf("%39s", ip);
    // Check IPv4 or IPv6 validity
    if (validate_ip_address(ip) || (inet_pton(AF_INET6, ip, &addr6) == 1))
    {
      valid = 1;
    }
    else
    {
      printf("Invalid IP address. Please re-enter:\n");
    }
  }
}
void InputProtocol(int *protocol, char *protocol_str)
{
  char choice;
  printf("Select Protocol:\n");
  printf("  [1] Any\n");
  printf("  [2] TCP\n");
  printf("  [3] UDP\n");
  printf("  [4] ICMP\n");
  printf("  [5] SCTP\n");
  printf("  [6] GRE\n");
  printf("  [7] ESP\n");
  printf("  [8] AH\n");
  printf("  [9] IPIP\n");
  printf("  [A] ICMPv6\n");
  printf("  [B] IGMP\n");
  printf("  [C] IPSec (custom)\n");
  printf("  [D] L2TP (custom)\n");
  printf("  [E] PPTP (custom)\n");
  scanf(" %c", &choice);

  switch (choice)
  {
  case '1':
    *protocol = 0;
    strcpy(protocol_str, "Any");
    break;
  case '2':
    *protocol = 6;
    strcpy(protocol_str, "TCP");
    break;
  case '3':
    *protocol = 17;
    strcpy(protocol_str, "UDP");
    break;
  case '4':
    *protocol = 1;
    strcpy(protocol_str, "ICMP");
    break;
  case '5':
    *protocol = 132;
    strcpy(protocol_str, "SCTP");
    break;
  case '6':
    *protocol = 47;
    strcpy(protocol_str, "GRE");
    break;
  case '7':
    *protocol = 50;
    strcpy(protocol_str, "ESP");
    break;
  case '8':
    *protocol = 51;
    strcpy(protocol_str, "AH");
    break;
  case '9':
    *protocol = 4;
    strcpy(protocol_str, "IPIP");
    break;
  case 'A':
  case 'a':
    *protocol = 58;
    strcpy(protocol_str, "ICMPv6");
    break;
  case 'B':
  case 'b':
    *protocol = 2;
    strcpy(protocol_str, "IGMP");
    break;
  case 'C':
  case 'c':
    printf("Enter custom protocol number for IPSec: ");
    scanf("%d", protocol);
    strcpy(protocol_str, "IPSec");
    break;
  case 'D':
  case 'd':
    printf("Enter custom protocol number for L2TP: ");
    scanf("%d", protocol);
    strcpy(protocol_str, "L2TP");
    break;
  case 'E':
  case 'e':
    printf("Enter custom protocol number for PPTP: ");
    scanf("%d", protocol);
    strcpy(protocol_str, "PPTP");
    break;
  default:
    printf("Invalid choice. Defaulting to TCP.\n");
    *protocol = 6;
    strcpy(protocol_str, "TCP");
  }
}

void save_port_mirroring_to_db(const PortMirroringConfig *cfg)
{
  sqlite3 *db;
  int rc = sqlite3_open(DB_PATH, &db);
  sqlite3_busy_timeout(db, 2000); 
  if (rc)
  {
    printf("Cannot open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  // Thử UPDATE trước, nếu không có dòng nào bị ảnh hưởng thì INSERT mới
  const char *update_sql =
      "UPDATE DeviceInterfaces SET "
      "InterfaceIsMirroring=?, InterfaceToMonitorInterfaceId=?, InterfaceMirrorSetting=?, MirrorType=?, Value=? "
      "WHERE InterfaceName=?";

  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK)
  {
    printf("SQL error: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }

  sqlite3_bind_int(stmt, 1, cfg->is_mirroring);
  sqlite3_bind_int(stmt, 2, cfg->monitor_target_id);
  sqlite3_bind_text(stmt, 3, cfg->mirror_setting, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, cfg->mirror_type, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 5, cfg->value, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 6, cfg->interface_name, -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  int rows_affected = sqlite3_changes(db);
  sqlite3_finalize(stmt);

  if (rows_affected == 0)
  {
    // Nếu chưa có, thì INSERT mới
    const char *insert_sql =
        "INSERT INTO DeviceInterfaces (InterfaceName, InterfaceIsMirroring, InterfaceToMonitorInterfaceId, InterfaceMirrorSetting, MirrorType, Value) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
      printf("SQL error: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return;
    }
    sqlite3_bind_text(stmt, 1, cfg->interface_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, cfg->is_mirroring);
    sqlite3_bind_int(stmt, 3, cfg->monitor_target_id);
    sqlite3_bind_text(stmt, 4, cfg->mirror_setting, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, cfg->mirror_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, cfg->value, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
      printf("Failed to insert data: %s\n", sqlite3_errmsg(db));
    }
    else
    {
      printf("Port mirroring configuration saved successfully!\n");
    }
    sqlite3_finalize(stmt);
  }
  else
  {
    printf("Port mirroring configuration updated successfully!\n");
  }

  sqlite3_close(db);
}
void save_port_config()
{
  FILE *file = fopen(CONFIG_FILE, "w");
  if (file != NULL)
  {
    fprintf(file, "%d", current_port);
    fclose(file);
  }
}

void load_port_config()
{
  FILE *file = fopen(CONFIG_FILE, "r");
  if (file != NULL)
  {
    fscanf(file, "%d", &current_port);
    fclose(file);
  }
}

// main C
int main()
{
  serial_port = configure_serial_port("/dev/ttyUSB0", B115200);
  // signal(SIGINT, handle_signal);
  // SIGTSTP
  signal(SIGTSTP, handle_signal);
  /******************************************************************/
  read_config_mode_save_logfile();
  read_threshold_from_file();
  read_threshold_timecounter_from_file();
  // load_port_config();  // Load saved port configuration
  create_http_filelog(LOGFILE_HTTP_IPv4);
  create_http_filelog(LOGFILE_HTTP_IPv6);
  ip_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  batch_queue = g_queue_new();
  load_ips_from_file(LOGFILE_HTTP_IPv4);
  load_ips_from_file(LOGFILE_HTTP_IPv6);
  send_http_ipv4_start(serial_port, LOGFILE_HTTP_IPv4);
  sleep(1);
  send_http_ipv6_start(serial_port, LOGFILE_HTTP_IPv6);
  previous_mode_fc();
  /******************************************************************/
  pthread_mutex_lock(&run_mutex);
  if (!is_run_running)
  {
    if (pthread_create(&run_thread, NULL, run, NULL) != 0)
    {
      perror("pthread_create");
      is_run_running = true;
      exit(1);
    }
  }
  pthread_mutex_unlock(&run_mutex);
  /******************************************************************/
  printf("\n 10");
  sleep(2);
  // Sync Time
  // send_data_sync_time(serial_port);
  // ModeStart_cnt(serial_port);
  new_menu(serial_port);
  // Mode_Condition_SDCard_Admin(serial_port);

  flush_batch_to_file(LOGFILE_HTTP_IPv4);
  flush_batch_to_file(LOGFILE_HTTP_IPv6);
  g_queue_free(batch_queue);
  g_hash_table_destroy(ip_table);
  if (pthread_join(run_thread, NULL) != 0)
  {
    perror("pthread_join");
    exit(1);
  }
  close(serial_port);
  return 0;
}
