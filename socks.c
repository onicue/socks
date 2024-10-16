#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <getopt.h>
#include "socks_info.h"

#define BUFSIZE 65536

#define IPV4_SIZE 4
#define IPV6_SIZE 16

#define log_info(...) log_message(1, __VA_ARGS__)
#define log_error(...) log_message(0, __VA_ARGS__)

// Default config

#define COLOR_ERROR "\033[31m"
#define COLOR_INFO  "\033[37m"
#define COLOR_CRITICAL "\033[31m"
#define COLOR_RESET "\033[0m"

char* socks_password = NULL;
char* socks_username = NULL;

unsigned short port = 8080; // default port
int listen_n = 30;  // max connections
int support_socks4 = 0;
int silent = 0; // if 1, then does not show the message
int no_ipv6 = 0;
int no_socks4 = 0;
int auth_method = NOAUTH;
int colorful_log = 0;

char* color_error = "";
char* color_info = "";
char* color_critical = "";
char* color_reset = "";

FILE *log_file;
pthread_mutex_t lock;

typedef struct {
  char* addr;
  unsigned char size;
  unsigned short port;
  int atype;
} address_t;

void log_message(int level, const char *message, ...)
{
  if (silent){
    return;
  }

  char vbuffer[255];
  va_list args;
  va_start(args, message);
  vsnprintf(vbuffer, sizeof(vbuffer), message, args);
  va_end(args);

  time_t now;
  time(&now);
  char *date = ctime(&now);
  date[strlen(date) - 1] = '\0';

  pthread_t self = pthread_self();

  pthread_mutex_lock(&lock);
  if (errno != 0 ) {
    fprintf(log_file, "%s[%s][%lu] Critical: %s - %s%s\n",
       color_critical, date, self, vbuffer, strerror(errno), color_reset);
    errno = 0;
  } else if (!level) {
    fprintf(log_file, "%s[%s][%lu] Error: %s%s\n",
        color_error, date, self, vbuffer, color_reset);
  } else if (level) {
    fprintf(log_file, "%s[%s][%lu] Info: %s%s\n",
        color_info, date, self, vbuffer, color_reset);
  } else {
    fprintf(log_file, "%s[%s][%lu] Critical: unknown log level%s\n",
       color_critical, date, self, color_reset);
  }
  pthread_mutex_unlock(&lock);
  fflush(log_file);
}

void socks_thread_exit(int fd){
  if ( fd >= 0){
    close(fd);
  }
  pthread_exit(NULL);
}

int nread(int fd, void* buf, int size){
  int readn = read(fd, buf, size);
  if (readn < 0) {
    log_error("error while reading");
    return -1;
  } else if (readn == 0) {
    // EOF, close the socket
    log_error("socket was closed");
    socks_thread_exit(fd);
  }
  return readn;
}

void nwrite(int fd, void* buf, int size) {
  int n = write(fd, buf, size);
  if (n < 0) {
    log_error("error while writing");
  }
}

void socks_initiation(int fd, int* version, int* methods){
  char data[2];
  int readn = read(fd, data, sizeof(data));
  if (readn != 2) {
    log_error("expected 2 bytes, got %d bytes", readn);
    socks_thread_exit(fd);
  }

  log_info("Initial %hhX %hhX", data[0], data[1]);
  *version = data[0];
  *methods = data[1];
}

void socks_send_auth_replie(int fd, int auth_code){
  char answer[2] = { VERSION5, auth_code };
  nwrite(fd, (void*) answer, sizeof(answer));
  log_info("Auth %hhX %hhX", answer[0], answer[1]);
}

char* socks_read_data(int fd) {
  unsigned char s;
  nread(fd, &s, sizeof(s));
  char* data = (char*) malloc(s + 1);
  nread(fd, data, s);
  data[s] = 0;
  return data;
}

void socks4_read_n(int fd, char* buf, int size){
  char ch = 0;
  for(int i = 0; i < size; ++i){
    nread(fd, &ch, sizeof(ch));
    buf[i] = ch;

    if (!ch) {
      break;
    }
  }
}

void socks4_send_response(int fd, int status) {
  char resp[8] = {0x00, (char)status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  nwrite(fd, (void*) resp, sizeof(resp));
}

void socks5_auth(int fd, int methods) {
  int support_auth = 0;
  for (int i = 0; i < methods; i++) {
    char method;
    nread(fd, (void*)&method, 1);
    log_info("Method AUTH %hhX", method);
    if (method == auth_method) {
      support_auth = 1;
    }
  }

  if (!support_auth) {
    log_info("Authentication not supported");
    socks_thread_exit(fd);
  }

  switch (auth_method) {
    case NOAUTH: {
      socks_send_auth_replie(fd, NOAUTH);
      break;
    }
    case USERPASS: {
      socks_send_auth_replie(fd, USERPASS);
      unsigned char ver;
      nread(fd, &ver, sizeof(ver));
      log_info("Auth ver: %hhX", ver);
      char* username = socks_read_data(fd);
      char* password = socks_read_data(fd);
      log_info("username: %s password: %s", username, password);
      if (!strcmp(socks_username, username) && !strcmp(socks_password, password)) {
        char answer[] = { VERSION5, OK };
        nwrite(fd, answer, sizeof(answer));
        free(username);
        free(password);
      } else {
        char answer[] = { VERSION5, FAILED };
        nwrite(fd, answer, sizeof(answer));
        free(username);
        free(password);
        socks_thread_exit(fd);
      }
      break;
    }
    default:
      log_error("auth failed");
      socks_send_auth_replie(fd, NOMETHOD);
      socks_thread_exit(fd);
  }
}

char socks5_get_cmd(int fd, int* atype){
  char data[4];
  if (nread(fd, (void*)data, sizeof(data)) < 0) {
    log_error("failed to read address type");
    socks_thread_exit(fd);
  }
  if (data[1] != CONNECT) {
    log_error("not supported command");
    socks_thread_exit(fd);
  }
  log_info("Command %hhX %hhX %hhX %hhX", data[0], data[1], data[2], data[3]);
  *atype = data[3];
  return data[1];
}

char* socks_get_ip(int fd, unsigned type_size) {
  char* ip = (char*) malloc(type_size);
  if (nread(fd, (void*)ip, type_size) < 0) {
    log_error("failed to read IP");
    free(ip);
    socks_thread_exit(fd);
  }

  if (!silent) {
    if (type_size == IPV4_SIZE) {
      log_info("IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
    } else if(type_size == IPV6_SIZE){
      char ip_str[INET6_ADDRSTRLEN];
      if (inet_ntop(AF_INET6, ip, ip_str, sizeof(ip_str)) != NULL) {
        log_info("IP [%s]", ip_str);
      } else {
        log_error("Failed to convert IPv6 address to string");
      }
    }
  }

  return ip;
}

unsigned short socks_get_port(int fd){
  unsigned short int p;
  if (nread(fd, (void*)&p, sizeof(p)) < 0) {
    log_error("failed to read port");
    socks_thread_exit(fd);
  }
  log_info("Port %hu", ntohs(p));
  return ntohs(p);
}

int socks_connect_domain(address_t* dest_addr){
  int fd;
  char port[6];
  struct addrinfo *serverinfo, *rp; // hints,
  snprintf(port, sizeof(port), "%d", dest_addr->port);
  /*memset(&hints, 0, sizeof(hints));*/
  /*hints.ai_family = AF_UNSPEC;*/
  /*hints.ai_socktype = SOCK_DGRAM; //SOCK_STREAM;*/
  if (getaddrinfo(dest_addr->addr, port, NULL, &serverinfo) != 0){
    log_error("getaddrinfo in socks_connect_domain");
    return -1;
  }

  for (rp=serverinfo; rp != NULL; rp = rp->ai_next) {
    if ((fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1){
      log_error("can't create socket in socks_connect_domain");
      continue;
    }
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break; /* Success */
    }

    close(fd);
  }

  freeaddrinfo(serverinfo);

  if (rp == NULL) {
    log_error("could not connect");
    return -1;
  }

  return fd;
}

int socks_connect_ipv4(address_t* dest_addr){
  int fd;
  struct sockaddr_in remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(dest_addr->addr);
  remote.sin_port = htons(dest_addr->port);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr*)&remote, sizeof(remote)) < 0) {
    log_error("while connecting in function socks_connect_ipv4");
    close(fd);
    return -1;
  }
  return fd;
}

int socks_connect_ipv6(address_t* dest_addr) {
  int fd;
  struct sockaddr_in6 remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin6_family = AF_INET6;
  memcpy(&remote.sin6_addr, dest_addr->addr, IPV6_SIZE);
  remote.sin6_port = htons(dest_addr->port);

  fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)&remote, sizeof(remote))) {
    log_error("while connecting in function socks_connect_ipv6");
    close(fd);
    return -1;
  }
  return fd;
}

void socks_send_replies(int fd, int rep, address_t* addr){
  char replies[4] = { VERSION5, rep, RESERVED, addr->atype };
  nwrite(fd, replies, sizeof(replies));
  if ( addr->atype == DOMAIN ) {
    nwrite(fd, &addr->size, sizeof(addr->size));
  }
  nwrite(fd, addr->addr, addr->size);
  nwrite(fd, &addr->port, sizeof(addr->port));
  log_info("Replies %hhX %hhX %hhX %hhX", replies[0], replies[1], replies[2], replies[3]);
}

void socks5_check_and_answer(int net_fd, int inet_fd, address_t* dest_addr){
  if (inet_fd < 0) {
    socks_send_replies(net_fd, FAILED, dest_addr);
    free(dest_addr->addr);
    socks_thread_exit(net_fd);
  }
  socks_send_replies(net_fd, OK, dest_addr);
  free(dest_addr->addr);
}

int is_socks4a(char *ip)
{
  return (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0);
}

void socket_pipe(int fd0, int fd1)
{
  int maxfd, ret;
  fd_set rd_set;
  size_t nread;
  char buffer_r[BUFSIZE];

  log_info("Connecting two sockets");

  maxfd = (fd0 > fd1) ? fd0 : fd1;
  while (1) {
    FD_ZERO(&rd_set);
    FD_SET(fd0, &rd_set);
    FD_SET(fd1, &rd_set);
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR) {
      continue;
    }

    if (FD_ISSET(fd0, &rd_set)) {
      nread = recv(fd0, buffer_r, BUFSIZE, 0);
      if (nread <= 0)
        break;
      send(fd1, (const void*)buffer_r, nread, 0);
    }

    if (FD_ISSET(fd1, &rd_set)) {
      nread = recv(fd1, buffer_r, BUFSIZE, 0);
      if (nread <= 0)
        break;
      send(fd0, (const void*)buffer_r, nread, 0);
    }
  }
}

void* thread_process(void* fd) {
  int net_fd = *(int*)fd;
  int version, methods, inet_fd = -1;
  socks_initiation(net_fd, &version, &methods);

  switch (version) {
    case VERSION5:
      socks5_auth(net_fd, methods);
      int atype;
      switch (socks5_get_cmd(net_fd, &atype)) {
        case CONNECT: {
          switch (atype) {
            case IPV4:{
              address_t dest_addr = {
                .atype = IPV4,
                .size = IPV4_SIZE,
              };
              dest_addr.addr = socks_get_ip(net_fd, IPV4_SIZE);
              dest_addr.port = socks_get_port(net_fd);

              inet_fd = socks_connect_ipv4(&dest_addr);
              socks5_check_and_answer(net_fd, inet_fd, &dest_addr);
              break;
            }
            case DOMAIN:{
              address_t dest_addr = {
                .atype = DOMAIN,
              };
              dest_addr.addr = socks_read_data(net_fd);
              dest_addr.port = socks_get_port(net_fd);

              inet_fd = socks_connect_domain(&dest_addr);
              socks5_check_and_answer(net_fd, inet_fd, &dest_addr);
              break;
            }
            case IPV6: {
              if(no_ipv6){
                log_info("IPv6 not supported");
                socks_thread_exit(net_fd);
              }
              address_t dest_addr = {
                .atype = IPV6,
                .size = IPV6_SIZE,
              };
              dest_addr.addr = socks_get_ip(net_fd, IPV6_SIZE);
              dest_addr.port = socks_get_port(net_fd);

              inet_fd = socks_connect_ipv6(&dest_addr);
              socks5_check_and_answer(net_fd, inet_fd, &dest_addr);
              break;
            }
            default:
              log_error("address type not supported");
              socks_thread_exit(net_fd);
          }
          break;
        }
        default:
          log_error("command not supported");
          socks_thread_exit(net_fd);
      }
      break;
    case VERSION4:{
      if(no_socks4){
        log_info("SOCKS4 not supported");
        socks_thread_exit(net_fd);
      }
      if (methods != 1) {
        log_error("unsupported command");
      } else {
        char ident[255];
        address_t dest_addr;
        dest_addr.port = socks_get_port(net_fd);
        dest_addr.addr = socks_get_ip(net_fd, IPV4_SIZE);

        socks4_read_n(net_fd, ident, sizeof(ident));

        if (is_socks4a(dest_addr.addr)) {
          char domain[255];
          socks4_read_n(net_fd, domain, sizeof(domain));
          log_info("socks4 ident:%s domain:%s", ident, domain);
          inet_fd = socks_connect_domain(&(address_t){.addr = domain, .port = dest_addr.port });
        } else {
          log_info("socks4 connecting");
          inet_fd = socks_connect_ipv4(&dest_addr);
        }

        if (-1 < inet_fd) {
          socks4_send_response(net_fd, 0x5a);
          free(dest_addr.addr);
        } else {
          socks4_send_response(net_fd, 0x5b);
          free(dest_addr.addr);
          socks_thread_exit(net_fd);
        }
      }
      break;
    }
    default:
      log_error("incorrect version");
      socks_thread_exit(net_fd);
  }

  socket_pipe(inet_fd, net_fd);
  close(inet_fd);
  socks_thread_exit(net_fd);
  return NULL;
}

void thread_handling() {
  int server_fd, net_fd;
  struct sockaddr_in address;
  socklen_t addrlen = sizeof(address);
  pthread_t thread;
  int opt = 1;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    log_error("socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET,
                SO_REUSEADDR | SO_REUSEPORT, &opt,
                sizeof(opt))) {
    log_error("setsockopt SOL_SOCKET");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt))){
    log_error("setsockopt SOL_TCP");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr*)&address, addrlen) < 0) {
    log_error("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, listen_n) < 0) {
    log_error("listen");
    exit(EXIT_FAILURE);
  }

  if (!silent) {
    printf("SOCKS proxy server started successfully on port %i\n", port);
  }

  while (1) {
    if ((net_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
      log_error("accept");
      exit(EXIT_FAILURE);
    }

    if (!pthread_create(&thread, NULL, &thread_process, &net_fd)) {
      pthread_detach(thread);
    } else {
      log_error("pthread create");
      exit(EXIT_FAILURE);
    }
  }
}

void set_auth_mode(){
  if(!auth_method)
    auth_method = 1;
}

void print_usage(){
  printf("Usage: socks [options]\n");
  printf("Options:\n");
  printf("  -h, --help              Show this help message\n");
  printf("  -f, --file FILE         Specify the file for log message (default is stdout)\n");
  printf("  -p, --port PORT         Specify the port (default is 8080)\n");
  printf("  -s, --silent            Disable log message\n");
  printf("  -n, --no-ipv6           Disable IPv6\n");
  printf("  -N, --no-socks4         Disable socks4 support\n");
  printf("  -A, --no-auth           Disable authentication\n");
  printf("  -C, --colorful          Enable colorful logs\n");
  printf("  -c, --connection        Set maximum connections\n");
  printf("The following options enable authentication:\n");
  printf("  -u, --username USER     Specify username (default is \"username\")\n");
  printf("  -w, --password PASS     Specify password (default is \"password\")\n");
  printf("  -S, --secret            Enter password\n");
  printf("  -a, --auth              Enable authentication\n");
}

int main(int argc, char* argv[]){
  int opt, opt_index = 0;
  log_file = stdout;
  socks_username = "username";
  socks_password = "password";
  pthread_mutex_init(&lock, NULL);
  signal(SIGPIPE, SIG_IGN);

  struct option options[] = {
    {"help", no_argument, 0, 'h'},
    {"file", required_argument, 0, 'f'},
    {"port", required_argument, 0, 'p'},
    {"silent", no_argument, 0, 's'},
    {"no-ipv6", no_argument, 0, 'n'},
    {"no-socks4", no_argument, 0, 'N'},
    {"username", required_argument, 0, 'u'},
    {"password", required_argument, 0, 'w'},
    {"secret", no_argument, 0, 'S'},
    {"auth", no_argument, 0, 'a'},
    {"no-auth", no_argument, 0, 'A'},
    {"colorful", no_argument, 0, 'C'},
    {"connection", required_argument, 0, 'c'}
  };

  while ((opt = getopt_long(argc, argv, "hf:p:su:w:SaACc:nN", options, &opt_index)) != -1) {
    switch (opt) {
      case 'h':
        print_usage();
        return 0;
      case 'f':
        log_file = fopen(optarg, "w");
        if (log_file == NULL) {
          perror("Error opening file");
          return 1;
        }
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 's':
        silent = 1;
        break;
      case 'u':
        socks_username = strdup(optarg);
        auth_method = USERPASS;
        break;
      case 'w':
        socks_password = strdup(optarg);
        auth_method = USERPASS;
        break;
      case'S':
        socks_password = strdup(getpass("Enter password:"));
        auth_method = USERPASS;
        break;
      case 'a':
        auth_method = USERPASS;
        break;
      case 'A':
        auth_method = NOAUTH;
        break;
      case 'C':
        colorful_log = 1;
        break;
      case 'c':
        listen_n = atoi(optarg);
        break;
      case 'n':
        no_ipv6 = 1;
        break;
      case 'N':
        no_socks4 = 1;
        break;
      default:
        print_usage();
        return 1;
    }
  }

  if (colorful_log) {
    color_info = COLOR_INFO;
    color_error = COLOR_ERROR;
    color_critical = COLOR_CRITICAL;
    color_reset = COLOR_RESET;
  }

  thread_handling();

  free(socks_username);
  free(socks_password);
  if(log_file != stdout) {
    fclose(log_file);
  }
  return 0;
}
