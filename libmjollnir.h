#ifndef __LIBMJOLLNIR_H__
#define __LIBMJOLLNIR_H_

/*
 * TOR access library
 * contacts: vlad.botanic@gmail.com, dbaryshkov@gmail.com
 *
 * License: GPLv2+ or MIT?
 *
 * Main exports and definitions
 */

struct _tor_context;
struct _tor_socket;

// flags? run only services?
enum tor_powers {
    TOR_CLIENT=1, TOR_SERVICE=2
};

struct _tor_config {
    enum tor_powers powers;
};

struct _tor_addr {

};

typedef struct _tor_context *ptor_context;
typedef struct _tor_socket *ptor_socket;
typedef struct _tor_config tor_config, *ptor_config;
typedef struct _tor_addr tor_addr, *ptor_addr;
typedef int (*tor_accept_fn)(ptor_socket sock_in);

int tor_setup(ptor_config _cfg, ptor_context *ctxt);
void tor_teardown(ptor_context ctxt);

// socket-like API?
int tor_socket(ptor_context ctxt, ptor_socket *sock);
int tor_connect(ptor_socket sock, ptor_addr addr);
int tor_send(ptor_socket sock, char *buffer, int size);
int tor_recv(ptor_socket sock, char *buffer, int size);
void tor_close(ptor_socket sock);

//todo: read about hidden services!
int tor_bind(ptor_socket sock, ptor_addr addr);
int tor_listen(ptor_socket sock, tor_accept_fn callback);
int tor_accept(ptor_socket sock);

#endif