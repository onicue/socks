#ifndef SOCKS_INFO
#define SOCKS_INFO

#define RESERVED 0x00

enum SOCKS {
  VERSION4 = 0x04,
  VERSION5 = 0x05
};

enum socks_auth {
  NOAUTH = 0x00,
  GSSAPI = 0x01,
  USERPASS = 0x02,
  //X'03' to X'7F' IANA ASSIGNED
  //X'80' to X'FE' RESERVED FOR PRIVATE METHODS
  NOMETHOD = 0xff
};

enum socks_auth_userpass {
  AUTH_OK = 0x00,
  AUTH_VERSION = 0x01,
  AUTH_FAIL = 0xff
};

enum socks_cmd {
  CONNECT = 0x01,
  //not supported commands
  /*BIND = 0x02,*/
  /*UDP_ASSOSIATE = 0x03*/
};

enum socks_atyp {
  IPV4 = 0x01,
  DOMAIN = 0x03,
  IPV6 = 0x04
};

enum socks_rep {
  OK = 0x00,
  FAILED = 0x05
  /*succeeded = 0x00,*/
  /*server_failure = 0x01, //general SOCKS server failure*/
  /*not_allowed = 0x02, //connection not allowed by ruleset*/
  /*network_unreachable = 0x03,*/
  /*host_unreachable = 0x04,*/
  /*connection_refused  = 0x05,*/
  /*ttl_expired = 0x06,*/
  /*cmd_not_supported = 0x07, //Command not supported*/
  /*addr_type_not_supported = 0x08, //Address type not supported*/
  /*ff_unassigned = 0x09 //to X'FF' unassigned*/
};
#endif
