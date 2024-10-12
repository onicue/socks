//default config
#include "socks_info.h"

#define COLOR_ERROR "\033[31m"
#define COLOR_INFO  "\033[37m"
#define COLOR_CRITICAL "\033[31m"
#define COLOR_RESET "\033[0m"

char* socks_password;
char* socks_username;

unsigned short port = 8080; //default port
int listen_n = 30;  //max connection

int support_socks4 = 0;
int silent = 0; // if 1, then does not show the message
int no_ipv6 = 0;
int auth_method = NOAUTH;

int colorful_log = 0;
