#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#if defined (_WIN32) || defined (_WIN64)
#include <windows.h> 
#else
#include <unistd.h>
#endif

#include <sodium.h> // just as an example
#include <ei.h>
#include "ed25519_drv.h"

#define HEADER_SIZE 4 // Can be 1, 2 or 4, set whiile opening port in Erlang

#if defined (_WIN32) || defined (_WIN64)
#  define DO_EXIT(code) do { ExitProcess((code)); exit((code));} while (0)
/* exit() called only to avoid a warning */
#else
#  define DO_EXIT(code) exit((code))
#endif

static ei_x_buff process(const byte *buf);
static ei_x_buff process_helo(const byte *_buf, int _index_start);
static ei_x_buff process_ed25519_keypair(const byte *buf, int index_start);
static ei_x_buff process_ed25519_seed_keypair(const byte *buf, int index_start);
static ei_x_buff process_keypairs(const byte *buf, int index_start);
static ei_x_buff process_seed_keypairs(const byte *buf, int index_start);
static ei_x_buff process_ed25519_pk_to_curve25519(const byte *buf, int index_start);
static ei_x_buff process_ed25519_sk_to_curve25519(const byte *buf, int index_start);
static ei_x_buff process_dh_scalarmult_base(const byte *buf, int index_start);
static ei_x_buff process_dh_scalarmult(const byte *buf, int index_start);
static ei_x_buff process_ed25519_sign(const byte *buf, int index_start);
static ei_x_buff process_ed25519_verify(const byte *buf, int index_start);
static ei_x_buff process_curve25519_verify(const byte *buf, int index_start);
static ei_x_buff make_error(const char *text);
static int get_key(const byte *buf, int *index, byte *key, const int len);
static byte *get_msg(const byte *buf, int *index, long *msglen);
static byte *read_port_msg(void);
static void write_port_msg(const ei_x_buff *result);
static int read_exact(byte *buffer, const int len);
static int write_exact(const byte *buffer, const int len);
static void *safe_malloc(const int size);

static int header_size = 4;
static unsigned int max_body_size = UINT_MAX; // This is insane large...

typedef struct _func {
  ei_x_buff (*func)(const byte *buf, int index_start);
  int arity;
} func_t;

static const func_t funcs[] = {
  {process_helo, 0},
  {process_ed25519_keypair, 0},
  {process_ed25519_seed_keypair, 1},
  {process_keypairs, 0},
  {process_seed_keypairs, 1},
  {process_ed25519_pk_to_curve25519, 1},
  {process_ed25519_sk_to_curve25519, 1},
  {process_dh_scalarmult_base, 1},
  {process_dh_scalarmult, 2},
  {process_ed25519_sign, 2},
  {process_ed25519_verify, 3},
  {process_curve25519_verify, 3}
};

static const int funcs_size = sizeof(funcs) / sizeof(funcs[0]);
 
int main(int argc, char *argv[]) {
  byte *buffer = NULL;
  ei_x_buff result;
    
#if defined (_WIN32) || defined (_WIN64)
  /* Attention Windows programmers: you need to explicitly set
   * mode of stdin/stdout to binary or else the port program won't work
   */
  setmode(fileno(stdout), O_BINARY);
  setmode(fileno(stdin), O_BINARY);
#endif

  if (sodium_init() == -1) {
    DO_EXIT(EXIT_OPEN_LIB);
  }

  if (argc == 2) {
    switch (atoi(argv[1])) {
    case 1:
      header_size = 1;
      max_body_size = UCHAR_MAX;
      break;
    case 2:
      header_size = 2;
      max_body_size = USHRT_MAX;
      break;
    case 4:
      header_size = 4;
      max_body_size = UINT_MAX;
      break;
    default:
      DO_EXIT(EXIT_HEADER_SIZE_ARG);
    }
  }

  for (;;) {
    buffer = read_port_msg();
    result = process(buffer);
    write_port_msg(&result);
    ei_x_free(&result);
    free(buffer);
  }
  return 0;
}

static ei_x_buff process(const byte *buf) {
  ei_x_buff result;

  int index = 0, ver = 0, arity = 0;
  long opcode;

  if (ei_decode_version((char *)buf, &index, &ver)) {
    result = make_error("data encoding version mismatch");
  } else if (ei_decode_tuple_header((char *)buf, &index, &arity)) {
    result = make_error("data must be a tuple");
  } else if (ei_decode_long((char *)buf, &index, &opcode)) {
    result = make_error("opcode must be an integer");
  } else {
    // arity check PLUS one for the opcode
    if (opcode >= 0 && opcode < funcs_size && arity == funcs[opcode].arity + 1) {
      result = funcs[opcode].func(buf, index);
    } else {
      result = make_error("unknown opcode or wrong arity");
    }
  }
  return result;
}

static ei_x_buff process_helo(const byte *_buf, int _index_start) {
  ei_x_buff result;
  
  ei_x_new_with_version(&result);
  ei_x_encode_atom(&result, "ok"); 
  return result;
}

static ei_x_buff process_ed25519_keypair(const byte *_buf, int _index_start) {
  ei_x_buff result;
  byte ed25519_pk[crypto_sign_PUBLICKEYBYTES];
  byte ed25519_sk[crypto_sign_SECRETKEYBYTES];

  // No input arguments

  crypto_sign_keypair((unsigned char *)ed25519_pk, 
		      (unsigned char *)ed25519_sk);

  ei_x_new_with_version(&result);
  ei_x_encode_tuple_header(&result, 2);
  ei_x_encode_atom(&result, "ok"); 
  ei_x_encode_tuple_header(&result, 2);
  ei_x_encode_binary(&result, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
  ei_x_encode_binary(&result, ed25519_sk, crypto_sign_SECRETKEYBYTES);
  return result;
}

static ei_x_buff process_keypairs(const byte *_buf, int _index_start) {
  ei_x_buff result;
  byte ed25519_pk[crypto_sign_PUBLICKEYBYTES],
    ed25519_sk[crypto_sign_SECRETKEYBYTES],
    curve25519_pk[crypto_scalarmult_curve25519_BYTES],
    curve25519_sk[crypto_scalarmult_curve25519_BYTES];

  // No input arguments

  crypto_sign_keypair((unsigned char *)ed25519_pk, 
		      (unsigned char *)ed25519_sk);

  crypto_sign_ed25519_pk_to_curve25519((unsigned char *)curve25519_pk, 
				       (unsigned char *)ed25519_pk);

  crypto_sign_ed25519_sk_to_curve25519((unsigned char *)curve25519_sk, 
				       (unsigned char *)ed25519_sk);

  ei_x_new_with_version(&result);
  ei_x_encode_tuple_header(&result, 3);
  ei_x_encode_atom(&result, "ok"); 
  ei_x_encode_tuple_header(&result, 2);
  ei_x_encode_binary(&result, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
  ei_x_encode_binary(&result, ed25519_sk, crypto_sign_SECRETKEYBYTES);
  ei_x_encode_tuple_header(&result, 2);
  ei_x_encode_binary(&result, curve25519_pk, crypto_scalarmult_curve25519_BYTES);
  ei_x_encode_binary(&result, curve25519_sk, crypto_scalarmult_curve25519_BYTES);
  return result;
}

static ei_x_buff process_ed25519_seed_keypair(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte seed[crypto_sign_SEEDBYTES],
    ed25519_pk[crypto_sign_PUBLICKEYBYTES],
    ed25519_sk[crypto_sign_SECRETKEYBYTES];

  // Seed

  if (get_key(buf, &index, seed, crypto_sign_SEEDBYTES)) {
    crypto_sign_seed_keypair((unsigned char *)ed25519_pk,
			     (unsigned char *)ed25519_sk,
			     (const unsigned char *)seed);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_binary(&result, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    ei_x_encode_binary(&result, ed25519_sk, crypto_sign_SECRETKEYBYTES);
  } else {
    result = make_error("Seed error");
  }
  return result;
}

static ei_x_buff process_seed_keypairs(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte seed[crypto_sign_SEEDBYTES],
    ed25519_pk[crypto_sign_PUBLICKEYBYTES],
    ed25519_sk[crypto_sign_SECRETKEYBYTES],
    curve25519_pk[crypto_scalarmult_curve25519_BYTES],
    curve25519_sk[crypto_scalarmult_curve25519_BYTES];

  // Seed

  if (get_key(buf, &index, seed, crypto_sign_SEEDBYTES)) {

    crypto_sign_seed_keypair((unsigned char *)ed25519_pk,
			     (unsigned char *)ed25519_sk,
			     (const unsigned char *)seed);

    crypto_sign_ed25519_pk_to_curve25519((unsigned char *)curve25519_pk, 
					 (const unsigned char *)ed25519_pk);
    
    crypto_sign_ed25519_sk_to_curve25519((unsigned char *)curve25519_sk, 
					 (const unsigned char *)ed25519_sk);
    
    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 3);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_binary(&result, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    ei_x_encode_binary(&result, ed25519_sk, crypto_sign_SECRETKEYBYTES);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_binary(&result, curve25519_pk, crypto_scalarmult_curve25519_BYTES);
    ei_x_encode_binary(&result, curve25519_sk, crypto_scalarmult_curve25519_BYTES);
  } else {
    result = make_error("Seed error");
  }
  return result;
}

static ei_x_buff process_ed25519_pk_to_curve25519(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  byte curve25519_pk[crypto_scalarmult_curve25519_BYTES];

  // Public_key

  if (get_key(buf, &index, ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES)) {

    crypto_sign_ed25519_pk_to_curve25519((unsigned char *)curve25519_pk, 
					 (const unsigned char *)ed25519_pk);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_binary(&result, curve25519_pk, crypto_scalarmult_curve25519_BYTES);
  } else {
    result = make_error("Key error");
  }
  return result;
}

static ei_x_buff process_ed25519_sk_to_curve25519(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
  byte curve25519_sk[crypto_scalarmult_curve25519_BYTES];

  // Secret_key

  if (get_key(buf, &index, ed25519_sk, crypto_sign_ed25519_SECRETKEYBYTES)) {

    crypto_sign_ed25519_sk_to_curve25519((unsigned char *)curve25519_sk, 
					 (const unsigned char *)ed25519_sk);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_binary(&result, curve25519_sk, crypto_scalarmult_curve25519_BYTES);
  } else {
    result = make_error("Key error");
  }
  return result;
}

static ei_x_buff process_dh_scalarmult_base(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte n[crypto_scalarmult_SCALARBYTES], // user's secret key
    q[crypto_scalarmult_BYTES];  // user's public key

  // Secret_key

  if (get_key(buf, &index, n, crypto_scalarmult_SCALARBYTES)) {
    
    crypto_scalarmult_base((unsigned char *)q, (const unsigned char *)n);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_binary(&result, q, crypto_scalarmult_BYTES);
  } else {
    result = make_error("Key error");
  }
  return result;
}

static ei_x_buff process_dh_scalarmult(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  byte n[crypto_scalarmult_SCALARBYTES], // user's secret key
    p[crypto_scalarmult_BYTES],  // other user's public key
    q[crypto_scalarmult_BYTES];  // secret shared by the two users

  // Secret_key, Public_key

  if (!get_key(buf, &index, n, crypto_scalarmult_SCALARBYTES)) {
    result = make_error("Secret key error");
  } else if (!get_key(buf, &index, p, crypto_scalarmult_SCALARBYTES)) {
    result = make_error("Public key error");
  } else {
    
    crypto_scalarmult_base((unsigned char *)q, (const unsigned char *)n);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_binary(&result, q, crypto_scalarmult_BYTES);
  }
  return result;
}

static ei_x_buff process_ed25519_sign(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  long msglen = 0;
  byte sk[crypto_sign_SECRETKEYBYTES], *msg, sig[crypto_sign_BYTES];

  // Private_key, Message

  if (!get_key(buf, &index, sk, crypto_sign_SECRETKEYBYTES)) {
    result = make_error("Secret key error");
  } else if ((msg = get_msg(buf, &index, &msglen)) == NULL) {
    result = make_error("Messgae error");
  } else {
    crypto_sign_detached((unsigned char *)sig,
    			 NULL,
    			 (const unsigned char *)msg,
    			 msglen,
    			 (const unsigned char *)sk);

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 
    ei_x_encode_binary(&result, sig, crypto_sign_BYTES);
    free(msg);
  }
  return result;
}

static ei_x_buff process_ed25519_verify(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  long msglen = 0;
  byte pk[crypto_sign_PUBLICKEYBYTES], *msg = NULL, sig[crypto_sign_BYTES];

  // Public_key, Message, Signature

  if (!get_key(buf, &index, pk, crypto_sign_PUBLICKEYBYTES)) {
    result = make_error("Public key error");
  } else if ((msg = get_msg(buf, &index, &msglen)) == NULL) {
    result = make_error("Msg error");
  } else if (!get_key(buf, &index, sig, crypto_sign_BYTES)) {
    result = make_error("Signature error");
  } else {

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 

    if (crypto_sign_verify_detached((const unsigned char *)sig, 
				    (const unsigned char *)msg, 
				    msglen, 
				    (const unsigned char *)pk) == 0) {
      ei_x_encode_boolean(&result, 1);
    } else {
      ei_x_encode_boolean(&result, 0);
    }
    free(msg);
  }
  return result;
}

static ei_x_buff process_curve25519_verify(const byte *buf, int index_start) {
  ei_x_buff result;
  int index = index_start;
  long msglen = 0;
  byte pk[crypto_scalarmult_SCALARBYTES], *msg = NULL, sig[crypto_sign_BYTES];

  // Public_key, Message, Signature

  if (!get_key(buf, &index, pk, crypto_scalarmult_SCALARBYTES)) {
    result = make_error("Public key error");
  } else if ((msg = get_msg(buf, &index, &msglen)) == NULL) {
    result = make_error("Msg error");
  } else if (!get_key(buf, &index, sig, crypto_sign_BYTES)) {
    result = make_error("Signature error");
  } else {

    ei_x_new_with_version(&result);
    ei_x_encode_tuple_header(&result, 2);
    ei_x_encode_atom(&result, "ok"); 

    if (crypto_sign_verify_curve25519_detached((const unsigned char *)sig, 
					       (const unsigned char *)msg, 
					       msglen, 
					       (const unsigned char *)pk) == 0) {
      ei_x_encode_boolean(&result, 1);
    } else {
      ei_x_encode_boolean(&result, 0);
    }
    free(msg);
  }
  return result;
}

static ei_x_buff make_error(const char *text) {
  ei_x_buff result;

  ei_x_new_with_version(&result);
  ei_x_encode_tuple_header(&result, 2);
  ei_x_encode_atom(&result, "error");
  ei_x_encode_string(&result, text);
  return result;
}

static int get_key(const byte *buf, int *index, byte *key, const int len) {
  int size = 0, _type;
  long _keylen = 0;

  ei_get_type((char *)buf, index, &_type, &size);
  if ((size != len) || (ei_decode_binary((char *)buf, index, key, &_keylen))) {
      return 0;
  } else {
    return size;
  }
}

static byte *get_msg(const byte *buf, int *index, long *msglen) {
  int size = 0, type = 0;
  byte *msg = NULL;

  ei_get_type((char *)buf, index, &type, &size);
  *msglen = (long) size;
  msg = safe_malloc(size + 1);
  if (ei_decode_string((char *)buf, index, msg)) {
    free(msg);
    return NULL;
  } else {
    return msg;
  }
}

/*Receive (read) data from erlang on stdin */
static byte *read_port_msg() {
  unsigned int len = 0, i;
  byte *buffer = NULL;
  byte hd[header_size];
  
  if(read_exact(hd, header_size) != header_size) {
    DO_EXIT(EXIT_STDIN_HEADER);
  }
  for (i = 0; i < header_size; ++i) {
    len <<= 8;
    len |= (unsigned char )hd[i];
  }
  if (len <= 0 || len > max_body_size) {
    DO_EXIT(EXIT_PACKET_SIZE);
  }
  buffer = safe_malloc(len);

  if (read_exact(buffer, len) <= 0) {
    DO_EXIT(EXIT_STDIN_BODY);
  }
  return buffer;
}

static void write_port_msg(const ei_x_buff *result) {
  byte hd[header_size];
  int i, s = result->buffsz;

  for (i = header_size - 1; i >= 0; --i) {
    hd[i] = s & 0xff;
    s >>= 8;
  }
  write_exact(hd, header_size);
  write_exact(result->buff, result->buffsz);
}

#ifdef WIN32
static int read_exact(byte *buffer, const int len) {
  HANDLE standard_input = GetStdHandle(STD_INPUT_HANDLE);
  
  unsigned read_result;
  unsigned sofar = 0;
  
  if (!len) { /* Happens for "empty packages */
    return 0;
  }
  for (;;) {
    if (!ReadFile(standard_input, buffer + sofar,
		  len - sofar, &read_result, NULL)) {
      return -1; /* EOF */
    }
    if (!read_result) {
      return -2; /* Interrupted while reading? */
    }
    sofar += read_result;
    if (sofar == len) {
      return len;
    }
  }
} 
#else
static int read_exact(byte *buffer, const int len) {
  int i, got = 0;
  
  do {
    if ((i = read(0, buffer + got, len - got)) <= 0)
      return(i);
    got += i;
  } while (got < len);
  return len;
}
#endif

#ifdef WIN32
static int write_exact(const byte *buffer, const int len) {
  HANDLE standard_output = GetStdHandle(STD_OUTPUT_HANDLE);
  
  unsigned write_result;
  unsigned wrote = 0;
  
  if (!len) { /* Happens for "empty packages */
    return 0;
  }
  for (;;) {
    if (!WriteFile(standard_output, buffer + wrote,
		  len - wrote, &write_result, NULL)) {
      return -1; /* EOF */
    }
    if (!write_result) {
      return -2; /* Interrupted while reading? */
    }
    wrote += write_result;
    if (wrote == len) {
      return len;
    }
  }
} 
#else
static int write_exact(const byte *buffer, const int len) {
  int i, wrote = 0;

  do {
    if ((i = write(1, buffer + wrote, len - wrote)) <= 0)
      return (i);
    wrote += i;
  } while (wrote < len);
  return len;
}
#endif

static void *safe_malloc(const int size) {
  void *memory = NULL;

  memory = malloc(size);
  if (memory == NULL) 
    DO_EXIT(EXIT_ALLOC);

  return memory;
}
