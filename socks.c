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
#include "socks_info.h"

#define BUFSIZE 65536

#define IPV4_SIZE 4
#define IPV6_SIZE 16

char* socks_password;
char* socks_username;

int daemon_mode = 0;
int support_socks4 = 0;
int quiet = 0; // if 1, then does not show the message

FILE *log_file;
pthread_mutex_t lock;

unsigned short port = 8080;
int listen_n = 30;

typedef struct {
  char* addr;
  unsigned char size;
  unsigned short port;
} address_t;

void log_message(const char *message, ...)
{
  if (quiet){
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
  if (errno != 0) {
    fprintf(log_file, "[%s][%lu] Critical: %s - %s\n", date, self, vbuffer, strerror(errno));
    errno = 0;
  } else {
    fprintf(log_file, "[%s][%lu] Info: %s\n", date, self, vbuffer);
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
    log_message("error while reading");
    return -1;
  } else if (readn == 0) {
    // EOF, close the socket
    log_message("Error: socket was closed");
    socks_thread_exit(fd);
  }
  return readn;
}

void nwrite(int fd, void* buf, int size) {
  int n = write(fd, buf, size);
  if (n < 0) {
    log_message("error while writing");
  }
}

void socks_initiation(int fd, int* version, int* methods){
  char data[2];
  int readn = read(fd, data, sizeof(data));
  if (readn != 2) {
    log_message("Error: expected 2 bytes, got %d bytes", readn);
    socks_thread_exit(fd);
  }

  log_message("Initial %hhX %hhX", data[0], data[1]);
  *version = data[0];
  *methods = data[1];
}

void socks_send_auth_replie(int fd, int auth_code){
  char answer[2] = { VERSION5, auth_code };
  nwrite(fd, (void*) answer, sizeof(answer));
  log_message("Auth %hhX %hhX", answer[0], answer[1]);
}

char* socks_read_data(int fd) {
  unsigned char s;
  nread(fd, &s, sizeof(s));
  char* data = (char*) malloc(s + 1);
  nread(fd, data, s);
  data[s] = 0;
  return data;
}

void socks5_auth(int fd, int methods) {
  int auth_method = NOAUTH;
  for (int i = 0; i < methods; i++) {
    char method;
    nread(fd, (void*)&method, 1);
    log_message("Method AUTH %hhX", method);
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
      log_message("Auth ver: %hhX", ver);
      char* username = socks_read_data(fd);
      char* password = socks_read_data(fd);
      log_message("username: %s password: %s", username, password);
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
      log_message("auth failed");
      socks_send_auth_replie(fd, NOMETHOD);
      socks_thread_exit(fd);
  }
}

char socks5_get_cmd(int fd, int* atype){
  char data[4];
  if (nread(fd, (void*)data, sizeof(data)) < 0) {
    log_message("Error: failed to read address type");
    socks_thread_exit(fd);
  }
  if (data[1] != CONNECT) {
    log_message("Not supported command");
    socks_thread_exit(fd);
  }
  log_message("Command %hhX %hhX %hhX %hhX", data[0], data[1], data[2], data[3]);
  *atype = data[3];
  return data[1];
}

char* socks_get_ip(int fd, unsigned type_size) {
  char* ip = (char*) malloc(type_size);
  if (nread(fd, (void*)ip, type_size) < 0) {
    log_message("Error: failed to read IP");
    free(ip);
    socks_thread_exit(fd);
  }
  if (type_size == IPV4_SIZE) {
    log_message("IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
  } else if(type_size == IPV6_SIZE){
    //TODO Handle IPv6 address logging
  }
  return ip;
}

unsigned short socks_get_port(int fd){
  unsigned short int p;
  if (nread(fd, (void*)&p, sizeof(p)) < 0) {
    log_message("Error: failed to read port");
    socks_thread_exit(fd);
  }
  log_message("Port %hu", ntohs(p));
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
    log_message("Error: getaddrinfo in socks_connect_domain");
    return -1;
  }

  for (rp=serverinfo; rp != NULL; rp = rp->ai_next) {
    if ((fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1){
      log_message("can't create socket in socks_connect_domain");
      continue;
    }
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break; /* Success */
    }

    close(fd);
  }

  freeaddrinfo(serverinfo);

  if (rp == NULL) {
    log_message("Error: could not connect");
    return -1;
  }

  return fd;
}

int socks_connect_ipv4(address_t* dest_addr){
  int fd;
  struct sockaddr_in remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  memcpy(&remote.sin_addr.s_addr, dest_addr->addr, IPV4_SIZE);
  remote.sin_port = htons(dest_addr->port);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr*)&remote, sizeof(remote)) < 0) {
    log_message("Error while connecting in function socks_connect");
    close(fd);
    return -1;
  }
  return fd;
}

void socks_send_replies(int fd, int rep, int atype, address_t addr){
  char replies[4] = { VERSION5, rep, RESERVED, atype };
  nwrite(fd, replies, sizeof(replies));
  if ( atype == DOMAIN ) {
    nwrite(fd, &addr.size, sizeof(addr.size));
  }
  nwrite(fd, addr.addr, addr.size);
  nwrite(fd, &addr.port, sizeof(addr.port));
  log_message("Replies %hhX %hhX %hhX %hhX", replies[0], replies[1], replies[2], replies[3]);
}

void socket_pipe(int fd0, int fd1)
{
  int maxfd, ret;
  fd_set rd_set;
  size_t nread;
  char buffer_r[BUFSIZE];

  log_message("Connecting two sockets");

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
                .size = IPV4_SIZE,
                .addr = socks_get_ip(net_fd, IPV4_SIZE),
                .port = socks_get_port(net_fd)
              };

              inet_fd = socks_connect_ipv4(&dest_addr);
              if (inet_fd < 0) {
                socks_send_replies(net_fd, FAILED, IPV4, dest_addr);
                free(dest_addr.addr);
                socks_thread_exit(net_fd);
              }
              socks_send_replies(net_fd, OK, IPV4, dest_addr);
              free(dest_addr.addr);
              break;
            }
            case DOMAIN:{
              address_t dest_addr;
              dest_addr.addr = socks_read_data(net_fd);
              dest_addr.port = socks_get_port(net_fd);
              inet_fd = socks_connect_domain(&dest_addr);
              if (inet_fd < 0) {
                socks_send_replies(net_fd, FAILED, DOMAIN, dest_addr);
                free(dest_addr.addr);
                socks_thread_exit(net_fd);
              }
              socks_send_replies(net_fd, OK, DOMAIN, dest_addr);
              free(dest_addr.addr);
              break;
            };
            default:
              log_message("Address type not supported");
              socks_thread_exit(net_fd);
          }
          socket_pipe(inet_fd, net_fd);
          close(inet_fd);
          break;
        }
        default:
          log_message("Command not supported");
          socks_thread_exit(net_fd);
      }
      break;
    case VERSION4:{
      if(!support_socks4) {
        log_message("SOCKS4 not supported");
        break;
      }

    }
    default:
      log_message("Incorrect version");
      socks_thread_exit(net_fd);
  }

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
    log_message("socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET,
                SO_REUSEADDR | SO_REUSEPORT, &opt,
                sizeof(opt))) {
    log_message("setsockopt SOL_SOCKET");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt))){
    log_message("setsockopt SOL_TCP");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr*)&address, addrlen) < 0) {
    log_message("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, listen_n) < 0) {
    log_message("listen");
    exit(EXIT_FAILURE);
  }

  while (1) {
    if ((net_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
      log_message("accept");
      exit(EXIT_FAILURE);
    }

    if (!pthread_create(&thread, NULL, &thread_process, &net_fd)) {
      pthread_detach(thread);
    } else {
      log_message("pthread create");
      exit(EXIT_FAILURE);
    }
  }
}

int main(){
  log_file = stdout;
  pthread_mutex_init(&lock, NULL);
  signal(SIGPIPE, SIG_IGN);
  thread_handling();
  return 0;
}
