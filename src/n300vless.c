#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#define N300VLESS_VERSION "0.6.3"
#define IO_BUFFER_SIZE 16384
#define MAX_HEADER_SIZE 8192
#define MAX_CONFIG_LINE 2048
#define MAX_HOST_SIZE 255
#define MAX_PATH_SIZE 1023
#define MAX_CLIENTS_HARD 48
#define HANDSHAKE_STAGGER_US 250000U
#define VISION_FLOW "xtls-rprx-vision"
#define VISION_FLOW_LENGTH 16
#define VISION_FRAME_SIZE 8192
#define VISION_FRAME_OVERHEAD 21
#define VISION_COMMAND_CONTINUE 0
#define VISION_COMMAND_END 1
#define VISION_COMMAND_DIRECT 2
#define GRPC_MESSAGE_CAPACITY (IO_BUFFER_SIZE + 64)
#define HTTP2_FRAME_MAX 16384

enum inbound_kind {
    INBOUND_SOCKS = 1,
    INBOUND_REDIRECT = 2
};

enum target_type {
    TARGET_IPV4 = 1,
    TARGET_DOMAIN = 2,
    TARGET_IPV6 = 3
};

struct config {
    char server[MAX_HOST_SIZE + 1];
    int server_port;
    unsigned char uuid[16];
    char transport[8];
    int use_tls;
    int use_reality;
    int use_vision;
    int reality_key_set;
    unsigned char reality_public_key[32];
    unsigned char reality_short_id[8];
    size_t reality_short_id_len;
    int insecure;
    char sni[MAX_HOST_SIZE + 1];
    char ws_host[MAX_HOST_SIZE + 1];
    char ws_path[MAX_PATH_SIZE + 1];
    char grpc_service[256];
    char grpc_authority[MAX_HOST_SIZE + 1];
    char ca_file[512];
    char socks_listen[64];
    int socks_port;
    char redirect_listen[64];
    int redirect_port;
    int max_clients;
    int connect_timeout;
    int idle_timeout;
};

struct target {
    enum target_type type;
    unsigned char address[256];
    size_t address_len;
    uint16_t port;
};

struct upstream {
    int fd;
    SSL *ssl;
    int use_tls;
    int use_ws;
    uint64_t ws_remaining;
    unsigned char ws_mask[4];
    unsigned int ws_mask_pos;
    int ws_masked;
    int use_grpc;
    uint32_t grpc_data_remaining;
    int grpc_data_end_stream;
    int grpc_eof;
    unsigned char grpc_message[GRPC_MESSAGE_CAPACITY];
    size_t grpc_message_length;
    size_t grpc_message_offset;
    int use_vision;
    unsigned char vision_uuid[16];
    int vision_write_started;
    unsigned int vision_write_packets;
    int vision_write_finished;
    int vision_write_direct;
    int vision_write_peer_command;
    int vision_read_started;
    int vision_read_have_frame;
    int vision_read_finished;
    int vision_read_direct;
    unsigned char vision_read_command;
    size_t vision_read_content;
    size_t vision_read_padding;
};

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t child_count;

static void log_line(const char *level, const char *message)
{
    time_t now = time(NULL);
    struct tm tm_value;
    char stamp[32];

    if (localtime_r(&now, &tm_value) != NULL) {
        strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm_value);
    } else {
        strcpy(stamp, "unknown-time");
    }
    fprintf(stderr, "%s n300vless[%ld] %s %s\n", stamp, (long)getpid(), level, message);
    fflush(stderr);
}

static void handle_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void handle_children(int signal_number)
{
    int saved_errno = errno;
    pid_t pid;

    (void)signal_number;
    do {
        pid = waitpid(-1, NULL, WNOHANG);
        if (pid > 0 && child_count > 0) {
            child_count--;
        }
    } while (pid > 0);
    errno = saved_errno;
}

static char *trim(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return text;
}

static int parse_boolean(const char *text, int *value)
{
    if (strcmp(text, "1") == 0 || strcasecmp(text, "true") == 0 || strcasecmp(text, "yes") == 0) {
        *value = 1;
        return 0;
    }
    if (strcmp(text, "0") == 0 || strcasecmp(text, "false") == 0 || strcasecmp(text, "no") == 0) {
        *value = 0;
        return 0;
    }
    return -1;
}

static int parse_integer(const char *text, int minimum, int maximum, int *value)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum || parsed > maximum) {
        return -1;
    }
    *value = (int)parsed;
    return 0;
}

static int copy_config_string(char *destination, size_t destination_size, const char *source)
{
    size_t length = strlen(source);

    if (length == 0 || length >= destination_size || strchr(source, '\r') != NULL || strchr(source, '\n') != NULL) {
        return -1;
    }
    memcpy(destination, source, length + 1);
    return 0;
}

static int hex_value(int character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int parse_uuid(const char *text, unsigned char uuid[16])
{
    char compact[33];
    size_t input_index;
    size_t output_index = 0;

    for (input_index = 0; text[input_index] != '\0'; input_index++) {
        if (text[input_index] == '-') {
            continue;
        }
        if (output_index >= 32 || hex_value((unsigned char)text[input_index]) < 0) {
            return -1;
        }
        compact[output_index++] = text[input_index];
    }
    if (output_index != 32) {
        return -1;
    }
    compact[32] = '\0';
    for (input_index = 0; input_index < 16; input_index++) {
        int high = hex_value((unsigned char)compact[input_index * 2]);
        int low = hex_value((unsigned char)compact[input_index * 2 + 1]);
        uuid[input_index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int parse_hex_bytes(const char *text, unsigned char *output, size_t capacity, size_t *output_length)
{
    size_t length = strlen(text);
    size_t index;

    if ((length & 1U) != 0 || length > capacity * 2) {
        return -1;
    }
    memset(output, 0, capacity);
    for (index = 0; index < length / 2; index++) {
        int high = hex_value((unsigned char)text[index * 2]);
        int low = hex_value((unsigned char)text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        output[index] = (unsigned char)((high << 4) | low);
    }
    *output_length = length / 2;
    return 0;
}

static int parse_base64url_32(const char *text, unsigned char output[32])
{
    char encoded[48];
    size_t length = strlen(text);
    size_t padded_length;
    size_t index;
    int decoded;

    if (length == 0 || length > 44) {
        return -1;
    }
    padded_length = (length + 3U) & ~3U;
    if (padded_length >= sizeof(encoded)) {
        return -1;
    }
    for (index = 0; index < length; index++) {
        unsigned char character = (unsigned char)text[index];
        if (character == '-') {
            encoded[index] = '+';
        } else if (character == '_') {
            encoded[index] = '/';
        } else if (isalnum(character) || character == '+' || character == '/') {
            encoded[index] = (char)character;
        } else {
            return -1;
        }
    }
    while (index < padded_length) {
        encoded[index++] = '=';
    }
    encoded[padded_length] = '\0';
    decoded = EVP_DecodeBlock(output, (const unsigned char *)encoded, (int)padded_length);
    if (decoded < 0) {
        return -1;
    }
    while (padded_length > 0 && encoded[padded_length - 1] == '=') {
        decoded--;
        padded_length--;
    }
    return decoded == 32 ? 0 : -1;
}

static void config_defaults(struct config *configuration)
{
    memset(configuration, 0, sizeof(*configuration));
    strcpy(configuration->transport, "tcp");
    strcpy(configuration->ws_path, "/");
    strcpy(configuration->grpc_service, "GunService");
    strcpy(configuration->ca_file, "/mnt/usb/n300vpn/certs/cacert.pem");
    strcpy(configuration->socks_listen, "127.0.0.1");
    configuration->socks_port = 10808;
    strcpy(configuration->redirect_listen, "0.0.0.0");
    configuration->redirect_port = 12345;
    configuration->max_clients = 4;
    configuration->connect_timeout = 8;
    configuration->idle_timeout = 300;
}

static int apply_config_value(struct config *configuration, const char *key, const char *value, char *error, size_t error_size)
{
    int result = 0;

    if (strcmp(key, "protocol") == 0) {
        result = strcasecmp(value, "vless") == 0 ? 0 : -1;
    } else if (strcmp(key, "server") == 0) {
        result = copy_config_string(configuration->server, sizeof(configuration->server), value);
    } else if (strcmp(key, "port") == 0) {
        result = parse_integer(value, 1, 65535, &configuration->server_port);
    } else if (strcmp(key, "uuid") == 0) {
        result = parse_uuid(value, configuration->uuid);
    } else if (strcmp(key, "transport") == 0) {
        if (strcasecmp(value, "tcp") != 0 && strcasecmp(value, "ws") != 0 &&
            strcasecmp(value, "grpc") != 0) {
            result = -1;
        } else {
            result = copy_config_string(configuration->transport, sizeof(configuration->transport), value);
        }
    } else if (strcmp(key, "tls") == 0) {
        result = parse_boolean(value, &configuration->use_tls);
    } else if (strcmp(key, "security") == 0) {
        if (strcasecmp(value, "none") == 0) {
            configuration->use_tls = 0;
            configuration->use_reality = 0;
        } else if (strcasecmp(value, "tls") == 0) {
            configuration->use_tls = 1;
            configuration->use_reality = 0;
        } else if (strcasecmp(value, "reality") == 0) {
            configuration->use_tls = 1;
            configuration->use_reality = 1;
        } else {
            result = -1;
        }
    } else if (strcmp(key, "reality_public_key") == 0) {
        result = parse_base64url_32(value, configuration->reality_public_key);
        if (result == 0) {
            configuration->reality_key_set = 1;
        }
    } else if (strcmp(key, "reality_short_id") == 0) {
        result = parse_hex_bytes(value, configuration->reality_short_id,
                                 sizeof(configuration->reality_short_id),
                                 &configuration->reality_short_id_len);
    } else if (strcmp(key, "insecure") == 0) {
        result = parse_boolean(value, &configuration->insecure);
    } else if (strcmp(key, "sni") == 0) {
        result = copy_config_string(configuration->sni, sizeof(configuration->sni), value);
    } else if (strcmp(key, "ws_host") == 0) {
        result = copy_config_string(configuration->ws_host, sizeof(configuration->ws_host), value);
    } else if (strcmp(key, "ws_path") == 0) {
        result = copy_config_string(configuration->ws_path, sizeof(configuration->ws_path), value);
    } else if (strcmp(key, "grpc_service") == 0) {
        result = copy_config_string(configuration->grpc_service, sizeof(configuration->grpc_service), value);
    } else if (strcmp(key, "grpc_authority") == 0) {
        result = copy_config_string(configuration->grpc_authority, sizeof(configuration->grpc_authority), value);
    } else if (strcmp(key, "ca_file") == 0) {
        result = copy_config_string(configuration->ca_file, sizeof(configuration->ca_file), value);
    } else if (strcmp(key, "socks_listen") == 0) {
        result = copy_config_string(configuration->socks_listen, sizeof(configuration->socks_listen), value);
    } else if (strcmp(key, "socks_port") == 0) {
        result = parse_integer(value, 1024, 65535, &configuration->socks_port);
    } else if (strcmp(key, "redirect_listen") == 0) {
        result = copy_config_string(configuration->redirect_listen, sizeof(configuration->redirect_listen), value);
    } else if (strcmp(key, "redirect_port") == 0) {
        result = parse_integer(value, 1024, 65535, &configuration->redirect_port);
    } else if (strcmp(key, "max_clients") == 0) {
        result = parse_integer(value, 1, MAX_CLIENTS_HARD, &configuration->max_clients);
    } else if (strcmp(key, "connect_timeout") == 0) {
        result = parse_integer(value, 2, 30, &configuration->connect_timeout);
    } else if (strcmp(key, "idle_timeout") == 0) {
        result = parse_integer(value, 30, 3600, &configuration->idle_timeout);
    } else if (strcmp(key, "flow") == 0) {
        if (value[0] == '\0' || strcasecmp(value, "none") == 0) {
            configuration->use_vision = 0;
        } else if (strcasecmp(value, VISION_FLOW) == 0) {
            configuration->use_vision = 1;
        } else {
            result = -1;
        }
    } else {
        snprintf(error, error_size, "unknown configuration key: %s", key);
        return -1;
    }

    if (result != 0) {
        snprintf(error, error_size, "invalid value for %s", key);
        return -1;
    }
    return 0;
}

static int load_config(const char *path, struct config *configuration, char *error, size_t error_size)
{
    FILE *file;
    char line[MAX_CONFIG_LINE];
    unsigned int line_number = 0;
    int saw_server = 0;
    int saw_port = 0;
    int saw_uuid = 0;

    config_defaults(configuration);
    file = fopen(path, "r");
    if (file == NULL) {
        snprintf(error, error_size, "cannot open configuration: %s", strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key;
        char *value;
        char *equals;

        line_number++;
        if (strchr(line, '\n') == NULL && !feof(file)) {
            snprintf(error, error_size, "configuration line %u is too long", line_number);
            fclose(file);
            return -1;
        }
        key = trim(line);
        if (*key == '\0' || *key == '#') {
            continue;
        }
        equals = strchr(key, '=');
        if (equals == NULL) {
            snprintf(error, error_size, "configuration line %u has no equals sign", line_number);
            fclose(file);
            return -1;
        }
        *equals = '\0';
        value = trim(equals + 1);
        key = trim(key);
        if (strcmp(key, "server") == 0) {
            saw_server = 1;
        } else if (strcmp(key, "port") == 0) {
            saw_port = 1;
        } else if (strcmp(key, "uuid") == 0) {
            saw_uuid = 1;
        }
        if (apply_config_value(configuration, key, value, error, error_size) != 0) {
            char detail[256];
            strncpy(detail, error, sizeof(detail) - 1);
            detail[sizeof(detail) - 1] = '\0';
            snprintf(error, error_size, "line %u: %s", line_number, detail);
            fclose(file);
            return -1;
        }
    }
    if (ferror(file)) {
        snprintf(error, error_size, "cannot read configuration: %s", strerror(errno));
        fclose(file);
        return -1;
    }
    fclose(file);
    if (!saw_server || !saw_port || !saw_uuid) {
        snprintf(error, error_size, "server, port and uuid are required");
        return -1;
    }
    if (configuration->use_tls && configuration->sni[0] == '\0') {
        strncpy(configuration->sni, configuration->server, sizeof(configuration->sni) - 1);
    }
    if (configuration->ws_host[0] == '\0') {
        strncpy(configuration->ws_host, configuration->server, sizeof(configuration->ws_host) - 1);
    }
    if (configuration->grpc_authority[0] == '\0') {
        strncpy(configuration->grpc_authority, configuration->sni, sizeof(configuration->grpc_authority) - 1);
    }
    if (configuration->ws_path[0] != '/') {
        snprintf(error, error_size, "ws_path must begin with a slash");
        return -1;
    }
    if (configuration->use_reality && !configuration->reality_key_set) {
        snprintf(error, error_size, "reality_public_key is required for REALITY");
        return -1;
    }
    if (configuration->use_reality && strcasecmp(configuration->transport, "tcp") != 0 &&
        strcasecmp(configuration->transport, "grpc") != 0) {
        snprintf(error, error_size, "REALITY currently requires tcp or grpc transport");
        return -1;
    }
    if (configuration->use_vision &&
        (strcasecmp(configuration->transport, "tcp") != 0 || !configuration->use_tls)) {
        snprintf(error, error_size, "Vision requires direct tcp transport with TLS or REALITY");
        return -1;
    }
    if (strcasecmp(configuration->transport, "grpc") == 0 &&
        (!configuration->use_tls || configuration->grpc_service[0] == '\0' ||
         strchr(configuration->grpc_service, '/') != NULL)) {
        snprintf(error, error_size, "gRPC requires TLS or REALITY and a simple service name");
        return -1;
    }
    return 0;
}

static int set_socket_timeouts(int fd, int seconds)
{
    struct timeval timeout;

    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return -1;
    }
    return 0;
}

static int connect_with_timeout(const char *host, int port, int timeout_seconds)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *current;
    char port_text[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_text, sizeof(port_text), "%d", port);
    if (getaddrinfo(host, port_text, &hints, &addresses) != 0) {
        return -1;
    }
    for (current = addresses; current != NULL; current = current->ai_next) {
        int flags;
        int result;
        fd_set write_set;
        struct timeval timeout;
        int socket_error = 0;
        socklen_t socket_error_size = sizeof(socket_error);

        fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (fd < 0) {
            continue;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        result = connect(fd, current->ai_addr, current->ai_addrlen);
        if (result != 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (result != 0) {
            FD_ZERO(&write_set);
            FD_SET(fd, &write_set);
            timeout.tv_sec = timeout_seconds;
            timeout.tv_usec = 0;
            result = select(fd + 1, NULL, &write_set, NULL, &timeout);
            if (result <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0 || socket_error != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        if (fcntl(fd, F_SETFL, flags) != 0 || set_socket_timeouts(fd, timeout_seconds) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(addresses);
    return fd;
}

static int read_exact_fd(int fd, unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = recv(fd, buffer + offset, length - offset, 0);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int write_all_fd(int fd, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = send(fd, buffer + offset, length - offset, MSG_NOSIGNAL);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int is_ipv4_text(const char *text)
{
    struct in_addr address;
    return inet_pton(AF_INET, text, &address) == 1;
}

static SSL_CTX *create_tls_context(const struct config *configuration, int reality_outer,
                                   char *error, size_t error_size)
{
    SSL_CTX *context;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    context = SSL_CTX_new(SSLv23_client_method());
    if (context == NULL) {
        snprintf(error, error_size, "SSL_CTX_new failed");
        return NULL;
    }
    SSL_CTX_set_options(context, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(context, SSL_MODE_RELEASE_BUFFERS);
    if (reality_outer) {
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
        if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1) {
            snprintf(error, error_size, "cannot restrict REALITY to TLS 1.3");
            SSL_CTX_free(context);
            return NULL;
        }
    } else if (configuration->insecure) {
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_load_verify_locations(context, configuration->ca_file, NULL) != 1) {
            snprintf(error, error_size, "cannot load CA file");
            SSL_CTX_free(context);
            return NULL;
        }
    }
    return context;
}

static ssize_t upstream_raw_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    if (connection->use_tls) {
        int result;
        int ssl_error;

        do {
            result = SSL_read(connection->ssl, buffer, (int)length);
        } while (result < 0 && SSL_get_error(connection->ssl, result) == SSL_ERROR_WANT_READ);
        if (result > 0) {
            return result;
        }
        ssl_error = SSL_get_error(connection->ssl, result);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        return -1;
    }
    for (;;) {
        ssize_t result = recv(connection->fd, buffer, length, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return result;
    }
}

static int upstream_raw_read_exact(struct upstream *connection, unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = upstream_raw_read(connection, buffer + offset, length - offset);
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int upstream_raw_write_all(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        int count;

        if (connection->use_tls) {
            count = SSL_write(connection->ssl, buffer + offset, (int)(length - offset));
            if (count <= 0) {
                int ssl_error = SSL_get_error(connection->ssl, count);
                if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
                    continue;
                }
                return -1;
            }
        } else {
            ssize_t sent = send(connection->fd, buffer + offset, length - offset, MSG_NOSIGNAL);
            if (sent < 0 && errno == EINTR) {
                continue;
            }
            if (sent <= 0) {
                return -1;
            }
            count = (int)sent;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int websocket_send_frame(struct upstream *connection, unsigned char opcode, const unsigned char *payload, size_t length)
{
    unsigned char header[14];
    unsigned char mask[4];
    unsigned char masked[IO_BUFFER_SIZE];
    size_t header_length;
    size_t index;

    if (length > sizeof(masked) || RAND_bytes(mask, sizeof(mask)) != 1) {
        return -1;
    }
    header[0] = (unsigned char)(0x80U | (opcode & 0x0fU));
    if (length <= 125) {
        header[1] = (unsigned char)(0x80U | length);
        header_length = 2;
    } else {
        header[1] = 0x80U | 126U;
        header[2] = (unsigned char)((length >> 8) & 0xffU);
        header[3] = (unsigned char)(length & 0xffU);
        header_length = 4;
    }
    memcpy(header + header_length, mask, sizeof(mask));
    header_length += sizeof(mask);
    for (index = 0; index < length; index++) {
        masked[index] = (unsigned char)(payload[index] ^ mask[index % 4]);
    }
    if (upstream_raw_write_all(connection, header, header_length) != 0) {
        return -1;
    }
    return upstream_raw_write_all(connection, masked, length);
}

static int websocket_begin_data_frame(struct upstream *connection)
{
    for (;;) {
        unsigned char header[2];
        unsigned char extended[8];
        unsigned char opcode;
        uint64_t length;
        int masked;

        if (upstream_raw_read_exact(connection, header, sizeof(header)) != 0) {
            return -1;
        }
        if ((header[0] & 0x70U) != 0) {
            return -1;
        }
        opcode = (unsigned char)(header[0] & 0x0fU);
        masked = (header[1] & 0x80U) != 0;
        length = header[1] & 0x7fU;
        if (length == 126) {
            if (upstream_raw_read_exact(connection, extended, 2) != 0) {
                return -1;
            }
            length = ((uint64_t)extended[0] << 8) | extended[1];
        } else if (length == 127) {
            int index;
            if (upstream_raw_read_exact(connection, extended, 8) != 0 || (extended[0] & 0x80U) != 0) {
                return -1;
            }
            length = 0;
            for (index = 0; index < 8; index++) {
                length = (length << 8) | extended[index];
            }
        }
        if (length > 16U * 1024U * 1024U) {
            return -1;
        }
        connection->ws_masked = masked;
        connection->ws_mask_pos = 0;
        if (masked && upstream_raw_read_exact(connection, connection->ws_mask, sizeof(connection->ws_mask)) != 0) {
            return -1;
        }
        if (opcode == 0x8U) {
            return 0;
        }
        if (opcode == 0x9U || opcode == 0xAU) {
            unsigned char control[125];
            size_t index;
            if (length > sizeof(control) || upstream_raw_read_exact(connection, control, (size_t)length) != 0) {
                return -1;
            }
            if (masked) {
                for (index = 0; index < (size_t)length; index++) {
                    control[index] ^= connection->ws_mask[index % 4];
                }
            }
            if (opcode == 0x9U && websocket_send_frame(connection, 0xAU, control, (size_t)length) != 0) {
                return -1;
            }
            continue;
        }
        if (opcode != 0x0U && opcode != 0x1U && opcode != 0x2U) {
            return -1;
        }
        connection->ws_remaining = length;
        if (length == 0) {
            continue;
        }
        return 1;
    }
}

static ssize_t upstream_stream_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    size_t index;
    ssize_t count;

    if (!connection->use_ws) {
        return upstream_raw_read(connection, buffer, length);
    }
    if (connection->ws_remaining == 0) {
        int result = websocket_begin_data_frame(connection);
        if (result <= 0) {
            return result;
        }
    }
    if ((uint64_t)length > connection->ws_remaining) {
        length = (size_t)connection->ws_remaining;
    }
    count = upstream_raw_read(connection, buffer, length);
    if (count <= 0) {
        return count;
    }
    if (connection->ws_masked) {
        for (index = 0; index < (size_t)count; index++) {
            buffer[index] ^= connection->ws_mask[(connection->ws_mask_pos + index) % 4];
        }
        connection->ws_mask_pos = (connection->ws_mask_pos + (unsigned int)count) % 4;
    }
    connection->ws_remaining -= (uint64_t)count;
    return count;
}

static int upstream_stream_read_exact(struct upstream *connection, unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = upstream_stream_read(connection, buffer + offset, length - offset);
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int upstream_stream_write(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    if (connection->use_ws) {
        return websocket_send_frame(connection, 0x2U, buffer, length);
    }
    return upstream_raw_write_all(connection, buffer, length);
}

static int http2_send_frame(struct upstream *connection, unsigned char type, unsigned char flags,
                            uint32_t stream, const unsigned char *payload, size_t length)
{
    unsigned char header[9];

    if (length > 0xffffffU || stream > 0x7fffffffU) {
        return -1;
    }
    header[0] = (unsigned char)(length >> 16);
    header[1] = (unsigned char)(length >> 8);
    header[2] = (unsigned char)length;
    header[3] = type;
    header[4] = flags;
    header[5] = (unsigned char)(stream >> 24) & 0x7fU;
    header[6] = (unsigned char)(stream >> 16);
    header[7] = (unsigned char)(stream >> 8);
    header[8] = (unsigned char)stream;
    if (upstream_raw_write_all(connection, header, sizeof(header)) != 0) {
        return -1;
    }
    return length == 0U ? 0 : upstream_raw_write_all(connection, payload, length);
}

static int hpack_integer(unsigned char *buffer, size_t capacity, size_t *offset,
                         uint32_t value, unsigned int prefix, unsigned char first)
{
    uint32_t maximum = (1U << prefix) - 1U;

    if (*offset >= capacity) {
        return -1;
    }
    if (value < maximum) {
        buffer[(*offset)++] = (unsigned char)(first | value);
        return 0;
    }
    buffer[(*offset)++] = (unsigned char)(first | maximum);
    value -= maximum;
    while (value >= 128U) {
        if (*offset >= capacity) {
            return -1;
        }
        buffer[(*offset)++] = (unsigned char)((value & 0x7fU) | 0x80U);
        value >>= 7;
    }
    if (*offset >= capacity) {
        return -1;
    }
    buffer[(*offset)++] = (unsigned char)value;
    return 0;
}

static int hpack_string(unsigned char *buffer, size_t capacity, size_t *offset, const char *value)
{
    size_t length = strlen(value);

    if (length > UINT32_MAX || hpack_integer(buffer, capacity, offset, (uint32_t)length, 7, 0) != 0 ||
        length > capacity - *offset) {
        return -1;
    }
    memcpy(buffer + *offset, value, length);
    *offset += length;
    return 0;
}

static int hpack_indexed(unsigned char *buffer, size_t capacity, size_t *offset, uint32_t index)
{
    return hpack_integer(buffer, capacity, offset, index, 7, 0x80U);
}

static int hpack_literal_indexed_name(unsigned char *buffer, size_t capacity, size_t *offset,
                                      uint32_t name_index, const char *value)
{
    return hpack_integer(buffer, capacity, offset, name_index, 4, 0) == 0 &&
           hpack_string(buffer, capacity, offset, value) == 0 ? 0 : -1;
}

static int hpack_literal_name(unsigned char *buffer, size_t capacity, size_t *offset,
                              const char *name, const char *value)
{
    return hpack_integer(buffer, capacity, offset, 0, 4, 0) == 0 &&
           hpack_string(buffer, capacity, offset, name) == 0 &&
           hpack_string(buffer, capacity, offset, value) == 0 ? 0 : -1;
}

static int grpc_handshake(struct upstream *connection, const struct config *configuration)
{
    static const unsigned char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    unsigned char settings[6] = {0x00, 0x02, 0, 0, 0, 0};
    unsigned char headers[2048];
    char path[512];
    size_t used = 0;

    if (snprintf(path, sizeof(path), "/%s/Tun", configuration->grpc_service) < 0 ||
        strlen(path) >= sizeof(path)) {
        return -1;
    }
    if (upstream_raw_write_all(connection, preface, sizeof(preface) - 1U) != 0 ||
        http2_send_frame(connection, 0x04U, 0, 0, settings, sizeof(settings)) != 0 ||
        hpack_indexed(headers, sizeof(headers), &used, 3) != 0 ||
        hpack_indexed(headers, sizeof(headers), &used, 7) != 0 ||
        hpack_literal_indexed_name(headers, sizeof(headers), &used, 4, path) != 0 ||
        hpack_literal_indexed_name(headers, sizeof(headers), &used, 1, configuration->grpc_authority) != 0 ||
        hpack_literal_indexed_name(headers, sizeof(headers), &used, 31, "application/grpc") != 0 ||
        hpack_literal_name(headers, sizeof(headers), &used, "te", "trailers") != 0 ||
        hpack_literal_indexed_name(headers, sizeof(headers), &used, 58, "grpc-go/1.64.0") != 0 ||
        http2_send_frame(connection, 0x01U, 0x04U, 1, headers, used) != 0) {
        return -1;
    }
    connection->use_grpc = 1;
    return 0;
}

static int http2_discard(struct upstream *connection, uint32_t length)
{
    unsigned char discarded[1024];

    while (length != 0U) {
        size_t wanted = length > sizeof(discarded) ? sizeof(discarded) : (size_t)length;
        if (upstream_raw_read_exact(connection, discarded, wanted) != 0) {
            return -1;
        }
        length -= (uint32_t)wanted;
    }
    return 0;
}

static int grpc_window_update(struct upstream *connection, uint32_t stream, uint32_t increment)
{
    unsigned char payload[4];

    if (increment == 0U || increment > 0x7fffffffU) {
        return -1;
    }
    payload[0] = (unsigned char)(increment >> 24) & 0x7fU;
    payload[1] = (unsigned char)(increment >> 16);
    payload[2] = (unsigned char)(increment >> 8);
    payload[3] = (unsigned char)increment;
    return http2_send_frame(connection, 0x08U, 0, stream, payload, sizeof(payload));
}

static int grpc_next_data_frame(struct upstream *connection)
{
    for (;;) {
        unsigned char header[9];
        unsigned char ping[8];
        uint32_t length;
        uint32_t stream;
        unsigned char type;
        unsigned char flags;

        if (connection->grpc_eof) {
            return 0;
        }
        if (upstream_raw_read_exact(connection, header, sizeof(header)) != 0) {
            return -1;
        }
        length = ((uint32_t)header[0] << 16) | ((uint32_t)header[1] << 8) | header[2];
        type = header[3];
        flags = header[4];
        stream = ((uint32_t)(header[5] & 0x7fU) << 24) | ((uint32_t)header[6] << 16) |
                 ((uint32_t)header[7] << 8) | header[8];
        if (length > 1048576U) {
            return -1;
        }
        if (type == 0x00U && stream == 1U) {
            if ((flags & 0x08U) != 0U) {
                return -1;
            }
            connection->grpc_data_remaining = length;
            connection->grpc_data_end_stream = (flags & 0x01U) != 0U;
            if (length != 0U) {
                return 1;
            }
            if (connection->grpc_data_end_stream) {
                connection->grpc_eof = 1;
                return 0;
            }
            continue;
        }
        if (type == 0x04U && stream == 0U) {
            if ((flags & 0x01U) != 0U) {
                if (length != 0U) {
                    return -1;
                }
            } else {
                if (http2_discard(connection, length) != 0 ||
                    http2_send_frame(connection, 0x04U, 0x01U, 0, NULL, 0) != 0) {
                    return -1;
                }
            }
            continue;
        }
        if (type == 0x06U && stream == 0U) {
            if (length != sizeof(ping) || upstream_raw_read_exact(connection, ping, sizeof(ping)) != 0) {
                return -1;
            }
            if ((flags & 0x01U) == 0U && http2_send_frame(connection, 0x06U, 0x01U, 0, ping, sizeof(ping)) != 0) {
                return -1;
            }
            continue;
        }
        if (http2_discard(connection, length) != 0) {
            return -1;
        }
        if ((type == 0x03U && stream == 1U) || type == 0x07U) {
            connection->grpc_eof = 1;
            return 0;
        }
    }
}

static ssize_t grpc_data_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    while (connection->grpc_data_remaining == 0U) {
        int result = grpc_next_data_frame(connection);
        if (result <= 0) {
            return result;
        }
    }
    if (length > connection->grpc_data_remaining) {
        length = connection->grpc_data_remaining;
    }
    {
        ssize_t count = upstream_raw_read(connection, buffer, length);
        if (count <= 0) {
            return count;
        }
        connection->grpc_data_remaining -= (uint32_t)count;
        if (grpc_window_update(connection, 0, (uint32_t)count) != 0 ||
            grpc_window_update(connection, 1, (uint32_t)count) != 0) {
            return -1;
        }
        if (connection->grpc_data_remaining == 0U && connection->grpc_data_end_stream) {
            connection->grpc_eof = 1;
        }
        return count;
    }
}

static int grpc_data_read_exact(struct upstream *connection, unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = grpc_data_read(connection, buffer + offset, length - offset);
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static size_t protobuf_varint(unsigned char output[5], uint32_t value)
{
    size_t used = 0;

    do {
        unsigned char byte = (unsigned char)(value & 0x7fU);
        value >>= 7;
        if (value != 0U) {
            byte |= 0x80U;
        }
        output[used++] = byte;
    } while (value != 0U && used < 5U);
    return used;
}

static int grpc_body_write(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    unsigned char wire[GRPC_MESSAGE_CAPACITY];
    unsigned char encoded_length[5];
    size_t encoded_size;
    size_t protobuf_length;
    size_t wire_length;
    size_t offset = 0;

    if (length > IO_BUFFER_SIZE) {
        return -1;
    }
    encoded_size = protobuf_varint(encoded_length, (uint32_t)length);
    protobuf_length = 1U + encoded_size + length;
    wire_length = 5U + protobuf_length;
    if (wire_length > sizeof(wire)) {
        return -1;
    }
    wire[0] = 0;
    wire[1] = (unsigned char)(protobuf_length >> 24);
    wire[2] = (unsigned char)(protobuf_length >> 16);
    wire[3] = (unsigned char)(protobuf_length >> 8);
    wire[4] = (unsigned char)protobuf_length;
    wire[5] = 0x0aU;
    memcpy(wire + 6, encoded_length, encoded_size);
    if (length != 0U) {
        memcpy(wire + 6U + encoded_size, buffer, length);
    }
    while (offset < wire_length) {
        size_t chunk = wire_length - offset;
        if (chunk > HTTP2_FRAME_MAX) {
            chunk = HTTP2_FRAME_MAX;
        }
        if (http2_send_frame(connection, 0x00U, 0, 1, wire + offset, chunk) != 0) {
            return -1;
        }
        offset += chunk;
    }
    return 0;
}

static int grpc_load_message(struct upstream *connection)
{
    unsigned char envelope[5];
    uint32_t message_length;
    size_t offset = 1;
    uint32_t data_length = 0;
    unsigned int shift = 0;

    if (grpc_data_read_exact(connection, envelope, sizeof(envelope)) != 0 || envelope[0] != 0) {
        return -1;
    }
    message_length = ((uint32_t)envelope[1] << 24) | ((uint32_t)envelope[2] << 16) |
                     ((uint32_t)envelope[3] << 8) | envelope[4];
    if (message_length == 0U || message_length > sizeof(connection->grpc_message) ||
        grpc_data_read_exact(connection, connection->grpc_message, message_length) != 0 ||
        connection->grpc_message[0] != 0x0aU) {
        return -1;
    }
    while (offset < message_length && shift <= 28U) {
        unsigned char byte = connection->grpc_message[offset++];
        data_length |= (uint32_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0U) {
            break;
        }
        shift += 7U;
    }
    if (offset > message_length || data_length != message_length - offset) {
        return -1;
    }
    connection->grpc_message_offset = offset;
    connection->grpc_message_length = message_length;
    return 0;
}

static ssize_t grpc_body_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    for (;;) {
        if (connection->grpc_message_offset < connection->grpc_message_length) {
            size_t available = connection->grpc_message_length - connection->grpc_message_offset;
            if (length > available) {
                length = available;
            }
            memcpy(buffer, connection->grpc_message + connection->grpc_message_offset, length);
            connection->grpc_message_offset += length;
            return (ssize_t)length;
        }
        connection->grpc_message_length = 0;
        connection->grpc_message_offset = 0;
        if (grpc_load_message(connection) != 0) {
            return connection->grpc_eof ? 0 : -1;
        }
    }
}

static int vless_transport_write(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    if (connection->use_grpc) {
        return grpc_body_write(connection, buffer, length);
    }
    return upstream_stream_write(connection, buffer, length);
}

static ssize_t vless_transport_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    if (connection->use_grpc) {
        return grpc_body_read(connection, buffer, length);
    }
    return upstream_stream_read(connection, buffer, length);
}

static int vless_transport_read_exact(struct upstream *connection, unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = vless_transport_read(connection, buffer + offset, length - offset);
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static ssize_t upstream_direct_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    for (;;) {
        ssize_t result = recv(connection->fd, buffer, length, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return result;
    }
}

static int upstream_direct_write_all(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    return write_all_fd(connection->fd, buffer, length);
}

static int vision_encode_frame(struct upstream *connection, const unsigned char *payload, size_t payload_length,
                               unsigned char command, unsigned char *frame, size_t capacity, size_t *frame_length)
{
    unsigned char random_value[2];
    size_t offset = 0;
    size_t prefix_length = connection->vision_write_started ? 0U : sizeof(connection->vision_uuid);
    size_t available;
    size_t padding_length;
    int long_padding;

    if (command > VISION_COMMAND_DIRECT || capacity < prefix_length + 5U ||
        payload_length > capacity - prefix_length - 5U) {
        return -1;
    }
    available = capacity - prefix_length - 5U - payload_length;
    if (RAND_bytes(random_value, sizeof(random_value)) != 1) {
        return -1;
    }
    long_padding = payload_length >= 2U && payload[0] == 0x16U && payload[1] == 0x03U;
    if (long_padding && payload_length < 900U) {
        padding_length = 900U - payload_length +
                         ((((size_t)random_value[0] << 8) | random_value[1]) % 500U);
    } else {
        padding_length = random_value[0];
    }
    if (padding_length > available) {
        padding_length = available;
    }
    if (prefix_length != 0U) {
        memcpy(frame + offset, connection->vision_uuid, prefix_length);
        offset += prefix_length;
    }
    frame[offset++] = command;
    frame[offset++] = (unsigned char)(payload_length >> 8);
    frame[offset++] = (unsigned char)(payload_length & 0xffU);
    frame[offset++] = (unsigned char)(padding_length >> 8);
    frame[offset++] = (unsigned char)(padding_length & 0xffU);
    if (payload_length != 0U) {
        memcpy(frame + offset, payload, payload_length);
        offset += payload_length;
    }
    if (padding_length != 0U) {
        if (RAND_bytes(frame + offset, (int)padding_length) != 1) {
            return -1;
        }
        offset += padding_length;
    }
    connection->vision_write_started = 1;
    connection->vision_write_packets++;
    *frame_length = offset;
    return 0;
}

static int vision_body_write(struct upstream *connection, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    if (!connection->use_vision) {
        return vless_transport_write(connection, buffer, length);
    }
    if (connection->vision_write_finished) {
        if (connection->vision_write_direct) {
            return upstream_direct_write_all(connection, buffer, length);
        }
        return upstream_stream_write(connection, buffer, length);
    }
    do {
        unsigned char frame[VISION_FRAME_SIZE];
        size_t maximum = VISION_FRAME_SIZE - VISION_FRAME_OVERHEAD;
        size_t chunk = length - offset;
        size_t frame_length;
        unsigned char command = VISION_COMMAND_CONTINUE;
        int is_last;

        if (chunk > maximum) {
            chunk = maximum;
        }
        is_last = offset + chunk == length;
        if (is_last && connection->vision_write_peer_command != VISION_COMMAND_CONTINUE) {
            command = (unsigned char)connection->vision_write_peer_command;
        }
        if (vision_encode_frame(connection, buffer == NULL ? NULL : buffer + offset, chunk,
                                command, frame, sizeof(frame), &frame_length) != 0 ||
            upstream_stream_write(connection, frame, frame_length) != 0) {
            return -1;
        }
        offset += chunk;
        if (command != VISION_COMMAND_CONTINUE) {
            connection->vision_write_finished = 1;
            connection->vision_write_direct = command == VISION_COMMAND_DIRECT;
        }
    } while (offset < length || (!connection->vision_write_started && length == 0U));
    return 0;
}

static int vision_initial_write(struct upstream *connection, const unsigned char *header, size_t header_length,
                                const unsigned char *payload, size_t payload_length)
{
    unsigned char combined[MAX_HEADER_SIZE + VISION_FRAME_SIZE];

    if (!connection->use_vision) {
        if (header_length + payload_length > sizeof(combined)) {
            return -1;
        }
        memcpy(combined, header, header_length);
        if (payload_length != 0U) {
            memcpy(combined + header_length, payload, payload_length);
        }
        return vless_transport_write(connection, combined, header_length + payload_length);
    }
    {
        size_t chunk = payload_length;
        size_t frame_length;
        if (chunk > VISION_FRAME_SIZE - VISION_FRAME_OVERHEAD) {
            chunk = VISION_FRAME_SIZE - VISION_FRAME_OVERHEAD;
        }
        if (header_length >= sizeof(combined) ||
            vision_encode_frame(connection, payload, chunk, VISION_COMMAND_CONTINUE,
                                combined + header_length, sizeof(combined) - header_length,
                                &frame_length) != 0) {
            return -1;
        }
        memcpy(combined, header, header_length);
        if (upstream_stream_write(connection, combined, header_length + frame_length) != 0) {
            return -1;
        }
        if (chunk < payload_length) {
            return vision_body_write(connection, payload + chunk, payload_length - chunk);
        }
    }
    return 0;
}

static int vision_read_frame_header(struct upstream *connection)
{
    unsigned char header[VISION_FRAME_OVERHEAD];
    size_t header_length = connection->vision_read_started ? 5U : VISION_FRAME_OVERHEAD;
    size_t offset = 0;

    if (upstream_stream_read_exact(connection, header, header_length) != 0) {
        return -1;
    }
    if (!connection->vision_read_started) {
        if (memcmp(header, connection->vision_uuid, sizeof(connection->vision_uuid)) != 0) {
            return -1;
        }
        offset = sizeof(connection->vision_uuid);
        connection->vision_read_started = 1;
    }
    connection->vision_read_command = header[offset++];
    if (connection->vision_read_command > VISION_COMMAND_DIRECT) {
        return -1;
    }
    connection->vision_read_content = ((size_t)header[offset] << 8) | header[offset + 1U];
    offset += 2U;
    connection->vision_read_padding = ((size_t)header[offset] << 8) | header[offset + 1U];
    connection->vision_read_have_frame = 1;
    return 0;
}

static int vision_complete_read_frame(struct upstream *connection)
{
    unsigned char discarded[1024];

    while (connection->vision_read_padding != 0U) {
        size_t wanted = connection->vision_read_padding;
        ssize_t count;
        if (wanted > sizeof(discarded)) {
            wanted = sizeof(discarded);
        }
        count = upstream_stream_read(connection, discarded, wanted);
        if (count <= 0) {
            return -1;
        }
        connection->vision_read_padding -= (size_t)count;
    }
    if (connection->vision_read_command != VISION_COMMAND_CONTINUE) {
        connection->vision_read_finished = 1;
        connection->vision_read_direct = connection->vision_read_command == VISION_COMMAND_DIRECT;
        if (!connection->vision_write_finished) {
            connection->vision_write_peer_command = connection->vision_read_command;
        }
    }
    connection->vision_read_have_frame = 0;
    return 0;
}

static ssize_t vision_body_read(struct upstream *connection, unsigned char *buffer, size_t length)
{
    if (!connection->use_vision) {
        return vless_transport_read(connection, buffer, length);
    }
    for (;;) {
        if (connection->vision_read_finished) {
            if (connection->vision_read_direct) {
                return upstream_direct_read(connection, buffer, length);
            }
            return upstream_stream_read(connection, buffer, length);
        }
        if (!connection->vision_read_have_frame && vision_read_frame_header(connection) != 0) {
            return -1;
        }
        if (connection->vision_read_content != 0U) {
            size_t wanted = connection->vision_read_content;
            ssize_t count;
            if (wanted > length) {
                wanted = length;
            }
            count = upstream_stream_read(connection, buffer, wanted);
            if (count <= 0) {
                return count;
            }
            connection->vision_read_content -= (size_t)count;
            if (connection->vision_read_content == 0U) {
                (void)vision_complete_read_frame(connection);
            }
            return count;
        }
        if (vision_complete_read_frame(connection) != 0) {
            return -1;
        }
    }
}

static int find_header_value(const char *headers, const char *name, char *value, size_t value_size)
{
    const char *line = strstr(headers, "\r\n");
    size_t name_length = strlen(name);

    if (line == NULL) {
        return -1;
    }
    line += 2;
    while (*line != '\0' && !(line[0] == '\r' && line[1] == '\n')) {
        const char *end = strstr(line, "\r\n");
        const char *content;
        size_t length;

        if (end == NULL) {
            return -1;
        }
        if (strncasecmp(line, name, name_length) == 0 && line[name_length] == ':') {
            content = line + name_length + 1;
            while (content < end && (*content == ' ' || *content == '\t')) {
                content++;
            }
            length = (size_t)(end - content);
            while (length > 0 && isspace((unsigned char)content[length - 1])) {
                length--;
            }
            if (length == 0 || length >= value_size) {
                return -1;
            }
            memcpy(value, content, length);
            value[length] = '\0';
            return 0;
        }
        line = end + 2;
    }
    return -1;
}

static int websocket_handshake(struct upstream *connection, const struct config *configuration)
{
    unsigned char random_key[16];
    char key[32];
    char expected[64];
    char actual[128];
    char request[2048];
    char response[MAX_HEADER_SIZE + 1];
    char accept_source[128];
    unsigned char accept_digest[SHA_DIGEST_LENGTH];
    size_t used = 0;
    int request_length;

    if (RAND_bytes(random_key, sizeof(random_key)) != 1) {
        return -1;
    }
    EVP_EncodeBlock((unsigned char *)key, random_key, sizeof(random_key));
    snprintf(accept_source, sizeof(accept_source), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    SHA1((const unsigned char *)accept_source, strlen(accept_source), accept_digest);
    EVP_EncodeBlock((unsigned char *)expected, accept_digest, sizeof(accept_digest));
    request_length = snprintf(
        request,
        sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
        configuration->ws_path,
        configuration->ws_host,
        key
    );
    if (request_length <= 0 || (size_t)request_length >= sizeof(request) ||
        upstream_raw_write_all(connection, (const unsigned char *)request, (size_t)request_length) != 0) {
        return -1;
    }
    while (used < MAX_HEADER_SIZE) {
        ssize_t count = upstream_raw_read(connection, (unsigned char *)response + used, 1);
        if (count != 1) {
            return -1;
        }
        used++;
        if (used >= 4 && memcmp(response + used - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    if (used >= MAX_HEADER_SIZE) {
        return -1;
    }
    response[used] = '\0';
    if (strstr(response, " 101 ") == NULL || find_header_value(response, "Sec-WebSocket-Accept", actual, sizeof(actual)) != 0 ||
        strcmp(expected, actual) != 0) {
        return -1;
    }
    connection->use_ws = 1;
    return 0;
}

static int verify_tls_peer(SSL *ssl, const char *hostname)
{
    X509 *certificate;
    int result;

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        return -1;
    }
    certificate = SSL_get_peer_certificate(ssl);
    if (certificate == NULL) {
        return -1;
    }
    if (is_ipv4_text(hostname)) {
        result = X509_check_ip_asc(certificate, hostname, 0);
    } else {
        result = X509_check_host(certificate, hostname, 0, 0, NULL);
    }
    X509_free(certificate);
    return result == 1 ? 0 : -1;
}

static int open_upstream(struct upstream *connection, const struct config *configuration, SSL_CTX *tls_context)
{
    int handshake_result;

    memset(connection, 0, sizeof(*connection));
    connection->use_vision = configuration->use_vision;
    memcpy(connection->vision_uuid, configuration->uuid, sizeof(connection->vision_uuid));
    connection->fd = connect_with_timeout(configuration->server, configuration->server_port, configuration->connect_timeout);
    if (connection->fd < 0) {
        fprintf(stderr, "upstream TCP connect to %s:%d failed: %s\n",
                configuration->server, configuration->server_port, strerror(errno));
        return -1;
    }
    connection->use_tls = configuration->use_tls;
    if (connection->use_tls) {
        connection->ssl = SSL_new(tls_context);
        if (connection->ssl == NULL) {
            close(connection->fd);
            connection->fd = -1;
            return -1;
        }
        SSL_set_fd(connection->ssl, connection->fd);
        if (!is_ipv4_text(configuration->sni)) {
            SSL_set_tlsext_host_name(connection->ssl, configuration->sni);
        }
        if (strcasecmp(configuration->transport, "grpc") == 0) {
            static const unsigned char alpn[] = {2, 'h', '2'};
            if (SSL_set_alpn_protos(connection->ssl, alpn, sizeof(alpn)) != 0) {
                fprintf(stderr, "cannot configure HTTP/2 ALPN\n");
                SSL_free(connection->ssl);
                close(connection->fd);
                connection->ssl = NULL;
                connection->fd = -1;
                return -1;
            }
        }
        if (configuration->use_reality &&
            SSL_set_reality(connection->ssl, configuration->reality_public_key,
                            configuration->reality_short_id,
                            configuration->reality_short_id_len, 26, 7, 28) != 1) {
            fprintf(stderr, "REALITY client setup failed\n");
            SSL_free(connection->ssl);
            close(connection->fd);
            connection->ssl = NULL;
            connection->fd = -1;
            return -1;
        }
        handshake_result = SSL_connect(connection->ssl);
        if (handshake_result != 1) {
            fprintf(stderr, "upstream TLS handshake failed: ssl_error=%d errno=%d\n",
                    SSL_get_error(connection->ssl, handshake_result), errno);
            ERR_print_errors_fp(stderr);
            SSL_free(connection->ssl);
            close(connection->fd);
            connection->ssl = NULL;
            connection->fd = -1;
            return -1;
        }
        if (configuration->use_reality && SSL_reality_verify_peer(connection->ssl) != 1) {
            fprintf(stderr, "REALITY peer authentication failed\n");
            SSL_free(connection->ssl);
            close(connection->fd);
            connection->ssl = NULL;
            connection->fd = -1;
            return -1;
        }
        if (!configuration->use_reality && !configuration->insecure &&
            verify_tls_peer(connection->ssl, configuration->sni) != 0) {
            fprintf(stderr, "upstream TLS certificate verification failed\n");
            SSL_free(connection->ssl);
            close(connection->fd);
            connection->ssl = NULL;
            connection->fd = -1;
            return -1;
        }
    }
    if (strcasecmp(configuration->transport, "ws") == 0 && websocket_handshake(connection, configuration) != 0) {
        if (connection->ssl != NULL) {
            SSL_free(connection->ssl);
        }
        close(connection->fd);
        connection->ssl = NULL;
        connection->fd = -1;
        return -1;
    }
    if (strcasecmp(configuration->transport, "grpc") == 0 && grpc_handshake(connection, configuration) != 0) {
        if (connection->ssl != NULL) {
            SSL_free(connection->ssl);
        }
        close(connection->fd);
        connection->ssl = NULL;
        connection->fd = -1;
        return -1;
    }
    return 0;
}

static void close_upstream(struct upstream *connection)
{
    if (connection->ssl != NULL) {
        if (!connection->vision_read_direct && !connection->vision_write_direct) {
            SSL_shutdown(connection->ssl);
        }
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }
    if (connection->fd >= 0) {
        close(connection->fd);
        connection->fd = -1;
    }
}

static int parse_socks_target(int client, struct target *target)
{
    unsigned char greeting[257];
    unsigned char request[4];
    unsigned char reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    size_t address_length;

    if (read_exact_fd(client, greeting, 2) != 0 || greeting[0] != 0x05 || greeting[1] == 0 ||
        read_exact_fd(client, greeting + 2, greeting[1]) != 0) {
        return -1;
    }
    if (memchr(greeting + 2, 0x00, greeting[1]) == NULL) {
        unsigned char failure[2] = {0x05, 0xff};
        write_all_fd(client, failure, sizeof(failure));
        return -1;
    }
    if (write_all_fd(client, reply, 2) != 0 || read_exact_fd(client, request, sizeof(request)) != 0 ||
        request[0] != 0x05 || request[1] != 0x01 || request[2] != 0x00) {
        return -1;
    }
    if (request[3] == 0x01) {
        target->type = TARGET_IPV4;
        address_length = 4;
    } else if (request[3] == 0x03) {
        if (read_exact_fd(client, greeting, 1) != 0 || greeting[0] == 0) {
            return -1;
        }
        target->type = TARGET_DOMAIN;
        address_length = greeting[0];
    } else if (request[3] == 0x04) {
        target->type = TARGET_IPV6;
        address_length = 16;
    } else {
        return -1;
    }
    if (read_exact_fd(client, target->address, address_length) != 0 || read_exact_fd(client, greeting, 2) != 0) {
        return -1;
    }
    target->address_len = address_length;
    target->port = (uint16_t)(((uint16_t)greeting[0] << 8) | greeting[1]);
    if (target->port == 0) {
        return -1;
    }
    return 0;
}

static int get_redirect_target(int client, struct target *target)
{
    struct sockaddr_in destination;
    socklen_t destination_size = sizeof(destination);

    memset(&destination, 0, sizeof(destination));
    if (getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &destination, &destination_size) != 0 || destination.sin_family != AF_INET) {
        return -1;
    }
    target->type = TARGET_IPV4;
    target->address_len = 4;
    memcpy(target->address, &destination.sin_addr, 4);
    target->port = ntohs(destination.sin_port);
    return target->port == 0 ? -1 : 0;
}

static int send_socks_success(int client)
{
    const unsigned char response[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return write_all_fd(client, response, sizeof(response));
}

static int build_vless_request(unsigned char *header, size_t capacity, const struct config *configuration,
                               const struct target *target, size_t *header_length)
{
    size_t offset = 0;
    unsigned char vless_type;
    size_t addons_length = configuration->use_vision ? (size_t)(2 + VISION_FLOW_LENGTH) : 0;

    if (capacity < 1 + 16 + 1 + addons_length + 1 + 2 + 1 + 1 + target->address_len) {
        return -1;
    }
    header[offset++] = 0x00;
    memcpy(header + offset, configuration->uuid, 16);
    offset += 16;
    header[offset++] = (unsigned char)addons_length;
    if (configuration->use_vision) {
        header[offset++] = 0x0a;
        header[offset++] = VISION_FLOW_LENGTH;
        memcpy(header + offset, VISION_FLOW, VISION_FLOW_LENGTH);
        offset += VISION_FLOW_LENGTH;
    }
    header[offset++] = 0x01;
    header[offset++] = (unsigned char)(target->port >> 8);
    header[offset++] = (unsigned char)(target->port & 0xffU);
    if (target->type == TARGET_IPV4) {
        vless_type = 0x01;
    } else if (target->type == TARGET_DOMAIN) {
        vless_type = 0x02;
    } else if (target->type == TARGET_IPV6) {
        vless_type = 0x03;
    } else {
        return -1;
    }
    header[offset++] = vless_type;
    if (target->type == TARGET_DOMAIN) {
        if (target->address_len == 0 || target->address_len > 255) {
            return -1;
        }
        header[offset++] = (unsigned char)target->address_len;
    }
    memcpy(header + offset, target->address, target->address_len);
    offset += target->address_len;
    *header_length = offset;
    return 0;
}

static int send_initial_vless_request(int client, enum inbound_kind kind, struct upstream *connection,
                                      const struct config *configuration, const struct target *target)
{
    unsigned char initial[IO_BUFFER_SIZE];
    size_t header_length;
    size_t payload_length = 0;
    fd_set read_set;
    struct timeval timeout;
    int selected;

    if (build_vless_request(initial, sizeof(initial), configuration, target, &header_length) != 0) {
        return -1;
    }
    if (kind == INBOUND_SOCKS && send_socks_success(client) != 0) {
        return -1;
    }
    FD_ZERO(&read_set);
    FD_SET(client, &read_set);
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    do {
        selected = select(client + 1, &read_set, NULL, NULL, &timeout);
    } while (selected < 0 && errno == EINTR);
    if (selected < 0) {
        return -1;
    }
    if (selected > 0) {
        ssize_t count = recv(client, initial + header_length, sizeof(initial) - header_length, 0);
        if (count <= 0) {
            return -1;
        }
        payload_length = (size_t)count;
    }
    return vision_initial_write(connection, initial, header_length,
                                initial + header_length, payload_length);
}

static int consume_vless_response(struct upstream *connection)
{
    unsigned char header[2];
    unsigned char addons[255];

    if (vless_transport_read_exact(connection, header, sizeof(header)) != 0) {
        fprintf(stderr, "VLESS response header read failed\n");
        return -1;
    }
    if (header[0] != 0x00) {
        fprintf(stderr, "VLESS response version is %u, expected 0\n", (unsigned int)header[0]);
        return -1;
    }
    if (header[1] > 0 && vless_transport_read_exact(connection, addons, header[1]) != 0) {
        fprintf(stderr, "VLESS response addons read failed: length=%u\n", (unsigned int)header[1]);
        return -1;
    }
    return 0;
}

struct tunnel_bio_data {
    struct upstream *connection;
    unsigned char vless_header[512];
    size_t vless_header_length;
    int header_sent;
    int response_consumed;
};

static int tunnel_bio_create(BIO *bio)
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    return 1;
}

static int tunnel_bio_destroy(BIO *bio)
{
    if (bio == NULL) {
        return 0;
    }
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static int tunnel_bio_write(BIO *bio, const char *buffer, int length)
{
    struct tunnel_bio_data *data = (struct tunnel_bio_data *)BIO_get_data(bio);

    if (data == NULL || buffer == NULL || length <= 0) {
        return 0;
    }
    if (!data->header_sent) {
        int status;
        status = vision_initial_write(data->connection, data->vless_header,
                                      data->vless_header_length,
                                      (const unsigned char *)buffer, (size_t)length);
        if (status != 0) {
            return -1;
        }
        data->header_sent = 1;
        return length;
    }
    return vision_body_write(data->connection, (const unsigned char *)buffer, (size_t)length) == 0 ? length : -1;
}

static int tunnel_bio_read(BIO *bio, char *buffer, int length)
{
    struct tunnel_bio_data *data = (struct tunnel_bio_data *)BIO_get_data(bio);
    ssize_t count;

    if (data == NULL || buffer == NULL || length <= 0 || !data->header_sent) {
        return -1;
    }
    if (!data->response_consumed) {
        if (consume_vless_response(data->connection) != 0) {
            return -1;
        }
        data->response_consumed = 1;
    }
    count = vision_body_read(data->connection, (unsigned char *)buffer, (size_t)length);
    return count > 0 ? (int)count : (int)count;
}

static long tunnel_bio_ctrl(BIO *bio, int command, long number, void *pointer)
{
    (void)bio;
    (void)number;
    (void)pointer;
    return command == BIO_CTRL_FLUSH ? 1L : 0L;
}

static BIO_METHOD *tunnel_bio_method(void)
{
    static BIO_METHOD *method;

    if (method == NULL) {
        method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "n300vless-tunnel");
        if (method == NULL ||
            BIO_meth_set_write(method, tunnel_bio_write) != 1 ||
            BIO_meth_set_read(method, tunnel_bio_read) != 1 ||
            BIO_meth_set_ctrl(method, tunnel_bio_ctrl) != 1 ||
            BIO_meth_set_create(method, tunnel_bio_create) != 1 ||
            BIO_meth_set_destroy(method, tunnel_bio_destroy) != 1) {
            return NULL;
        }
    }
    return method;
}

static int relay_connection(int client, struct upstream *connection, int idle_timeout)
{
    unsigned char buffer[IO_BUFFER_SIZE];
    int response_pending = 1;

    for (;;) {
        fd_set read_set;
        struct timeval timeout;
        int highest = client > connection->fd ? client : connection->fd;
        int selected;

        FD_ZERO(&read_set);
        FD_SET(client, &read_set);
        FD_SET(connection->fd, &read_set);
        timeout.tv_sec = idle_timeout;
        timeout.tv_usec = 0;
        selected = select(highest + 1, &read_set, NULL, NULL, &timeout);
        if (selected <= 0) {
            return selected == 0 ? 0 : -1;
        }
        if (FD_ISSET(client, &read_set)) {
            ssize_t count = recv(client, buffer, sizeof(buffer), 0);
            if (count <= 0 || vision_body_write(connection, buffer, (size_t)count) != 0) {
                return count == 0 ? 0 : -1;
            }
        }
        if (FD_ISSET(connection->fd, &read_set) || (connection->ssl != NULL && SSL_pending(connection->ssl) > 0)) {
            ssize_t count;
            if (response_pending) {
                if (consume_vless_response(connection) != 0) {
                    return -1;
                }
                response_pending = 0;
            }
            count = vision_body_read(connection, buffer, sizeof(buffer));
            if (count <= 0 || write_all_fd(client, buffer, (size_t)count) != 0) {
                return count == 0 ? 0 : -1;
            }
        }
    }
}

static int handle_client(int client, enum inbound_kind kind, const struct config *configuration, SSL_CTX *tls_context)
{
    struct target target;
    struct upstream upstream_connection;
    int result;

    memset(&target, 0, sizeof(target));
    if (set_socket_timeouts(client, configuration->connect_timeout) != 0) {
        return -1;
    }
    if (kind == INBOUND_SOCKS) {
        result = parse_socks_target(client, &target);
    } else {
        result = get_redirect_target(client, &target);
    }
    if (result != 0) {
        log_line("ERROR", "cannot parse inbound target");
        return -1;
    }
    if (open_upstream(&upstream_connection, configuration, tls_context) != 0) {
        log_line("ERROR", "cannot connect or complete upstream handshake");
        return -1;
    }
    if (send_initial_vless_request(client, kind, &upstream_connection, configuration, &target) != 0) {
        log_line("ERROR", "cannot send initial VLESS request");
        close_upstream(&upstream_connection);
        return -1;
    }
    set_socket_timeouts(client, 30);
    set_socket_timeouts(upstream_connection.fd, 30);
    result = relay_connection(client, &upstream_connection, configuration->idle_timeout);
    if (result != 0) {
        log_line("ERROR", "VLESS relay ended with an error");
    }
    close_upstream(&upstream_connection);
    return result;
}

static int create_listener(const char *address_text, int port)
{
    int fd;
    int enabled = 1;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, address_text, &address.sin_addr) != 1 || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int serve(const struct config *configuration)
{
    int socks_listener;
    int redirect_listener;
    SSL_CTX *tls_context = NULL;
    char error[256];
    struct sigaction action;

    if (configuration->use_tls) {
        tls_context = create_tls_context(configuration, configuration->use_reality, error, sizeof(error));
        if (tls_context == NULL) {
            log_line("ERROR", error);
            return 1;
        }
    }
    socks_listener = create_listener(configuration->socks_listen, configuration->socks_port);
    redirect_listener = create_listener(configuration->redirect_listen, configuration->redirect_port);
    if (socks_listener < 0 || redirect_listener < 0) {
        log_line("ERROR", "cannot create listening sockets");
        if (socks_listener >= 0) {
            close(socks_listener);
        }
        if (redirect_listener >= 0) {
            close(redirect_listener);
        }
        if (tls_context != NULL) {
            SSL_CTX_free(tls_context);
        }
        return 1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_stop;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_children;
    action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&action.sa_mask);
    sigaction(SIGCHLD, &action, NULL);
    log_line("INFO", "service ready");

    while (!stop_requested) {
        fd_set read_set;
        int highest = socks_listener > redirect_listener ? socks_listener : redirect_listener;
        int selected;
        int listener;
        enum inbound_kind kind;
        int client;
        pid_t child;

        FD_ZERO(&read_set);
        FD_SET(socks_listener, &read_set);
        FD_SET(redirect_listener, &read_set);
        selected = select(highest + 1, &read_set, NULL, NULL, NULL);
        if (selected < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_line("ERROR", "listener select failed");
            break;
        }
        if (FD_ISSET(socks_listener, &read_set)) {
            listener = socks_listener;
            kind = INBOUND_SOCKS;
        } else {
            listener = redirect_listener;
            kind = INBOUND_REDIRECT;
        }
        client = accept(listener, NULL, NULL);
        if (client < 0) {
            continue;
        }
        if (child_count >= configuration->max_clients) {
            log_line("WARN", "connection limit reached; client will retry");
            close(client);
            continue;
        }
        child = fork();
        if (child < 0) {
            close(client);
            continue;
        }
        if (child == 0) {
            int status;
            unsigned int stagger_slot = child_count > 5 ? 5U : (unsigned int)child_count;
            close(socks_listener);
            close(redirect_listener);
            if (stagger_slot > 0U) {
                usleep(stagger_slot * HANDSHAKE_STAGGER_US);
            }
            RAND_poll();
            status = handle_client(client, kind, configuration, tls_context);
            close(client);
            if (tls_context != NULL) {
                SSL_CTX_free(tls_context);
            }
            _exit(status == 0 ? 0 : 1);
        }
        child_count++;
        close(client);
    }
    close(socks_listener);
    close(redirect_listener);
    while (child_count > 0) {
        int status;
        pid_t child = wait(&status);
        if (child < 0 && errno != EINTR) {
            break;
        }
    }
    if (tls_context != NULL) {
        SSL_CTX_free(tls_context);
    }
    log_line("INFO", "service stopped");
    return 0;
}

static int probe_config(const struct config *configuration)
{
    static const char probe_host[] = "connectivitycheck.gstatic.com";
    static const char request[] =
        "GET /generate_204 HTTP/1.1\r\n"
        "Host: connectivitycheck.gstatic.com\r\n"
        "User-Agent: n300vless-probe/1.0\r\n"
        "Connection: close\r\n\r\n";
    struct target target;
    struct upstream connection;
    SSL_CTX *tls_context = NULL;
    unsigned char initial[1024];
    unsigned char response[2049];
    size_t header_length;
    size_t used = 0;
    struct timeval started;
    struct timeval finished;
    long elapsed_ms;
    char error[256];
    int result = 1;

    memset(&target, 0, sizeof(target));
    target.type = TARGET_DOMAIN;
    target.address_len = strlen(probe_host);
    memcpy(target.address, probe_host, target.address_len);
    target.port = 80;
    if (configuration->use_tls) {
        tls_context = create_tls_context(configuration, configuration->use_reality, error, sizeof(error));
        if (tls_context == NULL) {
            fprintf(stderr, "probe TLS context error: %s\n", error);
            return 1;
        }
    }
    gettimeofday(&started, NULL);
    if (open_upstream(&connection, configuration, tls_context) != 0) {
        fprintf(stderr, "probe upstream handshake failed\n");
        goto done;
    }
    set_socket_timeouts(connection.fd, configuration->connect_timeout);
    if (build_vless_request(initial, sizeof(initial), configuration, &target, &header_length) != 0 ||
        header_length + sizeof(request) - 1 > sizeof(initial)) {
        fprintf(stderr, "probe request construction failed\n");
        close_upstream(&connection);
        goto done;
    }
    if (vision_initial_write(&connection, initial, header_length,
                             (const unsigned char *)request, sizeof(request) - 1) != 0 ||
        consume_vless_response(&connection) != 0) {
        fprintf(stderr, "probe VLESS exchange failed\n");
        close_upstream(&connection);
        goto done;
    }
    while (used < sizeof(response) - 1) {
        ssize_t count = vision_body_read(&connection, response + used, sizeof(response) - 1 - used);
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
        response[used] = '\0';
        if (strstr((const char *)response, "\r\n\r\n") != NULL) {
            break;
        }
    }
    close_upstream(&connection);
    gettimeofday(&finished, NULL);
    elapsed_ms = (finished.tv_sec - started.tv_sec) * 1000L + (finished.tv_usec - started.tv_usec) / 1000L;
    response[used] = '\0';
    if (used == 0 || (strncmp((const char *)response, "HTTP/1.1 204", 12) != 0 &&
                      strncmp((const char *)response, "HTTP/1.0 204", 12) != 0)) {
        fprintf(stderr, "probe received no valid HTTP 204 response\n");
        goto done;
    }
    printf("probe_ok=1 latency_ms=%ld bytes=%lu\n", elapsed_ms, (unsigned long)used);
    result = 0;

done:
    if (tls_context != NULL) {
        SSL_CTX_free(tls_context);
    }
    return result;
}

static int probe_endpoint_config(const struct config *configuration)
{
    struct timeval started;
    struct timeval finished;
    long elapsed_ms;
    int timeout_seconds = configuration->connect_timeout;
    int fd;

    if (timeout_seconds > 2) {
        timeout_seconds = 2;
    }
    if (timeout_seconds < 1) {
        timeout_seconds = 1;
    }
    gettimeofday(&started, NULL);
    fd = connect_with_timeout(configuration->server, configuration->server_port, timeout_seconds);
    gettimeofday(&finished, NULL);
    if (fd < 0) {
        fprintf(stderr, "endpoint connection failed\n");
        return 1;
    }
    close(fd);
    elapsed_ms = (finished.tv_sec - started.tv_sec) * 1000L +
                 (finished.tv_usec - started.tv_usec) / 1000L;
    if (elapsed_ms < 0) {
        elapsed_ms = 0;
    }
    printf("endpoint_ok=1 latency_ms=%ld\n", elapsed_ms);
    return 0;
}

static int valid_dns_name(const char *name)
{
    size_t index;
    size_t length = strlen(name);

    if (length == 0U || length > 253U) {
        return 0;
    }
    for (index = 0; index < length; index++) {
        unsigned char character = (unsigned char)name[index];
        if (!isalnum(character) && character != '.' && character != '-') {
            return 0;
        }
    }
    return 1;
}

static int resolve_a_doh(const char *hostname, const char *ca_file)
{
    static const char doh_name[] = "dns.google";
    static const char *doh_addresses[] = {"8.8.8.8", "8.8.4.4"};
    struct config tls_configuration;
    SSL_CTX *context = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    char request[768];
    unsigned char response[16385];
    size_t request_length;
    size_t request_offset = 0;
    size_t used = 0;
    char error[256];
    char *cursor;
    char address[INET_ADDRSTRLEN];
    size_t address_length;
    size_t address_index;
    int result = 1;

    if (!valid_dns_name(hostname) || ca_file[0] == '\0' || strlen(ca_file) >= sizeof(tls_configuration.ca_file)) {
        fprintf(stderr, "invalid DNS-over-HTTPS arguments\n");
        return 1;
    }
    memset(&tls_configuration, 0, sizeof(tls_configuration));
    strcpy(tls_configuration.ca_file, ca_file);
    context = create_tls_context(&tls_configuration, 0, error, sizeof(error));
    if (context == NULL) {
        fprintf(stderr, "DNS-over-HTTPS TLS context error: %s\n", error);
        return 1;
    }
    for (address_index = 0; address_index < sizeof(doh_addresses) / sizeof(doh_addresses[0]); address_index++) {
        fd = connect_with_timeout(doh_addresses[address_index], 443, 5);
        if (fd >= 0) {
            break;
        }
    }
    if (fd < 0) {
        fprintf(stderr, "DNS-over-HTTPS endpoint connection failed\n");
        goto done;
    }
    ssl = SSL_new(context);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 || SSL_set_tlsext_host_name(ssl, doh_name) != 1 ||
        SSL_connect(ssl) != 1 || verify_tls_peer(ssl, doh_name) != 0) {
        fprintf(stderr, "DNS-over-HTTPS TLS handshake failed\n");
        goto done;
    }
    snprintf(request, sizeof(request),
             "GET /resolve?name=%s&type=A HTTP/1.1\r\n"
             "Host: dns.google\r\n"
             "Accept: application/dns-json\r\n"
             "User-Agent: n300vless/%s\r\n"
             "Connection: close\r\n\r\n",
             hostname, N300VLESS_VERSION);
    request_length = strlen(request);
    while (request_offset < request_length) {
        int count = SSL_write(ssl, request + request_offset, (int)(request_length - request_offset));
        if (count <= 0) {
            fprintf(stderr, "DNS-over-HTTPS request failed\n");
            goto done;
        }
        request_offset += (size_t)count;
    }
    while (used < sizeof(response) - 1U) {
        int count = SSL_read(ssl, response + used, (int)(sizeof(response) - 1U - used));
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
    }
    response[used] = '\0';
    if (used == 0U || (strstr((const char *)response, "HTTP/1.1 200") == NULL &&
                       strstr((const char *)response, "HTTP/1.0 200") == NULL)) {
        fprintf(stderr, "DNS-over-HTTPS returned no valid HTTP 200 response\n");
        goto done;
    }
    cursor = (char *)response;
    for (;;) {
        cursor = strstr(cursor, "\"data\"");
        if (cursor == NULL) {
            break;
        }
        cursor = strchr(cursor, ':');
        if (cursor == NULL) {
            break;
        }
        cursor++;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\"') {
            cursor++;
        }
        address_length = 0;
        while (cursor[address_length] != '\0' && cursor[address_length] != '\"' &&
               cursor[address_length] != ',' && address_length < sizeof(address) - 1U) {
            address[address_length] = cursor[address_length];
            address_length++;
        }
        address[address_length] = '\0';
        if (is_ipv4_text(address)) {
            printf("resolved_ip=%s\n", address);
            result = 0;
            break;
        }
        cursor += address_length;
    }
    if (result != 0) {
        fprintf(stderr, "DNS-over-HTTPS response contained no IPv4 address\n");
    }

done:
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
    SSL_CTX_free(context);
    return result;
}

static int fetch_crunch_subscription(const char *url_file, const char *resolved_ip,
                                     const char *output_path, const char *ca_file)
{
    static const char url_prefix[] = "https://crunch-crunch.com";
    static const char server_name[] = "crunch-crunch.com";
    static const size_t maximum_body = 4U * 1024U * 1024U;
    struct config tls_configuration;
    FILE *url_stream = NULL;
    FILE *output_stream = NULL;
    SSL_CTX *context = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    char url[2048];
    const char *path;
    char request[2560];
    size_t request_length;
    size_t request_offset = 0;
    unsigned char buffer[IO_BUFFER_SIZE];
    unsigned char header[MAX_HEADER_SIZE + 1];
    size_t header_used = 0;
    size_t body_written = 0;
    size_t expected_body = 0;
    unsigned long parsed_content_length = 0;
    int header_complete = 0;
    char content_length[64];
    char error[256];
    int result = 1;

    if (!is_ipv4_text(resolved_ip) || ca_file[0] == '\0') {
        fprintf(stderr, "invalid HTTPS fetch arguments\n");
        return 1;
    }
    url_stream = fopen(url_file, "rb");
    if (url_stream == NULL || fgets(url, sizeof(url), url_stream) == NULL) {
        fprintf(stderr, "cannot read subscription URL file\n");
        goto done;
    }
    fclose(url_stream);
    url_stream = NULL;
    url[strcspn(url, "\r\n")] = '\0';
    if (strncmp(url, url_prefix, sizeof(url_prefix) - 1U) != 0 ||
        url[sizeof(url_prefix) - 1U] != '/' ||
        strpbrk(url + sizeof(url_prefix) - 1U, " \t\r\n") != NULL) {
        fprintf(stderr, "subscription URL is not allowed\n");
        goto done;
    }
    path = url + sizeof(url_prefix) - 1U;
    memset(&tls_configuration, 0, sizeof(tls_configuration));
    if (strlen(ca_file) >= sizeof(tls_configuration.ca_file)) {
        fprintf(stderr, "CA file path is too long\n");
        goto done;
    }
    strcpy(tls_configuration.ca_file, ca_file);
    context = create_tls_context(&tls_configuration, 0, error, sizeof(error));
    if (context == NULL) {
        fprintf(stderr, "HTTPS fetch TLS context error: %s\n", error);
        goto done;
    }
    fd = connect_with_timeout(resolved_ip, 443, 6);
    if (fd < 0) {
        fprintf(stderr, "HTTPS fetch endpoint connection failed\n");
        goto done;
    }
    ssl = SSL_new(context);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 || SSL_set_tlsext_host_name(ssl, server_name) != 1 ||
        SSL_connect(ssl) != 1 || verify_tls_peer(ssl, server_name) != 0) {
        fprintf(stderr, "HTTPS fetch TLS handshake failed\n");
        goto done;
    }
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: crunch-crunch.com\r\n"
             "User-Agent: Happ/1.0 n300vpn\r\n"
             "Accept: application/json\r\n"
             "Accept-Encoding: identity\r\n"
             "Connection: close\r\n\r\n",
             path);
    request_length = strlen(request);
    while (request_offset < request_length) {
        int count = SSL_write(ssl, request + request_offset, (int)(request_length - request_offset));
        if (count <= 0) {
            fprintf(stderr, "HTTPS fetch request failed\n");
            goto done;
        }
        request_offset += (size_t)count;
    }

    while (body_written <= maximum_body) {
        int count = SSL_read(ssl, buffer, sizeof(buffer));
        size_t offset = 0;
        if (count <= 0) {
            break;
        }
        if (!header_complete) {
            const unsigned char *header_end;
            if (header_used + (size_t)count > MAX_HEADER_SIZE) {
                fprintf(stderr, "HTTPS fetch response headers are too large\n");
                goto done;
            }
            memcpy(header + header_used, buffer, (size_t)count);
            header_used += (size_t)count;
            header[header_used] = '\0';
            header_end = (const unsigned char *)strstr((const char *)header, "\r\n\r\n");
            if (header_end == NULL) {
                continue;
            }
            offset = (size_t)(header_end - header) + 4U;
            if (strncmp((const char *)header, "HTTP/1.1 200", 12) != 0 &&
                strncmp((const char *)header, "HTTP/1.0 200", 12) != 0) {
                fprintf(stderr, "HTTPS fetch returned no HTTP 200 response\n");
                goto done;
            }
            if (find_header_value((const char *)header, "Content-Length", content_length, sizeof(content_length)) != 0 ||
                sscanf(content_length, "%lu", &parsed_content_length) != 1 ||
                parsed_content_length < 256UL || parsed_content_length > (unsigned long)maximum_body) {
                fprintf(stderr, "HTTPS fetch returned an invalid content length\n");
                goto done;
            }
            expected_body = (size_t)parsed_content_length;
            output_stream = fopen(output_path, "wb");
            if (output_stream == NULL) {
                fprintf(stderr, "cannot create HTTPS fetch output file\n");
                goto done;
            }
            header_complete = 1;
            if (header_used > offset) {
                size_t initial_body = header_used - offset;
                if (initial_body > expected_body || fwrite(header + offset, 1, initial_body, output_stream) != initial_body) {
                    fprintf(stderr, "cannot write HTTPS fetch output\n");
                    goto done;
                }
                body_written += initial_body;
            }
            continue;
        }
        if (body_written + (size_t)count > expected_body ||
            fwrite(buffer, 1, (size_t)count, output_stream) != (size_t)count) {
            fprintf(stderr, "HTTPS fetch body is larger than expected\n");
            goto done;
        }
        body_written += (size_t)count;
        if (body_written == expected_body) {
            break;
        }
    }
    if (!header_complete || body_written != expected_body || fflush(output_stream) != 0) {
        fprintf(stderr, "HTTPS fetch response ended early\n");
        goto done;
    }
    printf("fetch_ok=1 bytes=%lu\n", (unsigned long)body_written);
    result = 0;

done:
    if (output_stream != NULL) {
        fclose(output_stream);
    }
    if (result != 0) {
        remove(output_path);
    }
    if (url_stream != NULL) {
        fclose(url_stream);
    }
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
    if (context != NULL) {
        SSL_CTX_free(context);
    }
    return result;
}

static int probe_https_target(const struct config *configuration, const char *host, const char *request,
                              size_t minimum_body, long *elapsed_result, size_t *bytes_result)
{
    struct target target;
    struct upstream connection;
    struct tunnel_bio_data tunnel_data;
    SSL_CTX *outer_context = NULL;
    SSL_CTX *inner_context = NULL;
    SSL *inner_ssl = NULL;
    BIO *tunnel_bio = NULL;
    unsigned char response[8193];
    size_t request_offset = 0;
    size_t used = 0;
    size_t response_header_length = 0;
    struct timeval started;
    struct timeval finished;
    long elapsed_ms;
    char error[256];
    int http_status = 0;
    int result = 1;

    memset(&target, 0, sizeof(target));
    target.type = TARGET_DOMAIN;
    target.address_len = strlen(host);
    if (target.address_len == 0U || target.address_len > sizeof(target.address)) {
        return 1;
    }
    memcpy(target.address, host, target.address_len);
    target.port = 443;
    memset(&tunnel_data, 0, sizeof(tunnel_data));

    inner_context = create_tls_context(configuration, 0, error, sizeof(error));
    if (inner_context == NULL) {
        fprintf(stderr, "HTTPS inner TLS context error for %s: %s\n", host, error);
        return 1;
    }
    if (configuration->use_tls) {
        outer_context = create_tls_context(configuration, configuration->use_reality, error, sizeof(error));
        if (outer_context == NULL) {
            fprintf(stderr, "HTTPS outer TLS context error for %s: %s\n", host, error);
            goto done;
        }
    }
    if (build_vless_request(tunnel_data.vless_header, sizeof(tunnel_data.vless_header),
                            configuration, &target, &tunnel_data.vless_header_length) != 0) {
        fprintf(stderr, "HTTPS VLESS request construction failed for %s\n", host);
        goto done;
    }

    gettimeofday(&started, NULL);
    if (open_upstream(&connection, configuration, outer_context) != 0) {
        fprintf(stderr, "HTTPS upstream handshake failed for %s\n", host);
        goto done;
    }
    set_socket_timeouts(connection.fd, configuration->connect_timeout);
    tunnel_data.connection = &connection;
    tunnel_bio = BIO_new(tunnel_bio_method());
    inner_ssl = SSL_new(inner_context);
    if (tunnel_bio == NULL || inner_ssl == NULL) {
        fprintf(stderr, "HTTPS inner TLS allocation failed for %s\n", host);
        goto close_connection;
    }
    BIO_set_data(tunnel_bio, &tunnel_data);
    BIO_set_init(tunnel_bio, 1);
    SSL_set_bio(inner_ssl, tunnel_bio, tunnel_bio);
    tunnel_bio = NULL;
    SSL_set_tlsext_host_name(inner_ssl, host);
    if (SSL_connect(inner_ssl) != 1 ||
        (!configuration->insecure && verify_tls_peer(inner_ssl, host) != 0)) {
        fprintf(stderr, "HTTPS handshake failed for %s\n", host);
        goto close_connection;
    }
    while (request_offset < strlen(request)) {
        int count = SSL_write(inner_ssl, request + request_offset,
                              (int)(strlen(request) - request_offset));
        if (count <= 0) {
            fprintf(stderr, "HTTPS request failed for %s\n", host);
            goto close_connection;
        }
        request_offset += (size_t)count;
    }
    while (used < sizeof(response) - 1) {
        int count = SSL_read(inner_ssl, response + used, (int)(sizeof(response) - 1 - used));
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
        response[used] = '\0';
        if (response_header_length == 0U) {
            const char *end = strstr((const char *)response, "\r\n\r\n");
            if (end != NULL) {
                response_header_length = (size_t)(end - (const char *)response) + 4U;
            }
        }
        if (response_header_length != 0U && used >= response_header_length + minimum_body) {
            break;
        }
    }
    gettimeofday(&finished, NULL);
    elapsed_ms = (finished.tv_sec - started.tv_sec) * 1000L +
                 (finished.tv_usec - started.tv_usec) / 1000L;
    response[used] = '\0';
    if (used == 0 || sscanf((const char *)response, "HTTP/%*u.%*u %d", &http_status) != 1 || http_status != 200) {
        size_t preview = used < 120U ? used : 120U;
        fprintf(stderr, "HTTPS target %s returned no valid HTTP 200 response: bytes=%lu preview=%.*s\n",
                host, (unsigned long)used, (int)preview, (const char *)response);
        goto close_connection;
    }
    if (response_header_length == 0U || used < response_header_length + minimum_body) {
        fprintf(stderr, "HTTPS target %s returned too little body data: bytes=%lu required=%lu\n",
                host, (unsigned long)(used - response_header_length), (unsigned long)minimum_body);
        goto close_connection;
    }
    *elapsed_result = elapsed_ms;
    *bytes_result = used;
    result = 0;

close_connection:
    if (inner_ssl != NULL) {
        SSL_free(inner_ssl);
        inner_ssl = NULL;
    }
    if (tunnel_bio != NULL) {
        BIO_free(tunnel_bio);
        tunnel_bio = NULL;
    }
    close_upstream(&connection);
done:
    if (outer_context != NULL) {
        SSL_CTX_free(outer_context);
    }
    if (inner_context != NULL) {
        SSL_CTX_free(inner_context);
    }
    return result;
}

static int probe_youtube_config(const struct config *configuration)
{
    static const char page_request[] =
        "GET /watch?v=cQk4Uw77siY HTTP/1.1\r\n"
        "Host: www.youtube.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n";
    static const char media_request[] =
        "GET /report_mapping HTTP/1.1\r\n"
        "Host: redirector.googlevideo.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n";
    long page_ms = 0;
    long media_ms = 0;
    size_t page_bytes = 0;
    size_t media_bytes = 0;

    if (probe_https_target(configuration, "www.youtube.com", page_request, 0,
                           &page_ms, &page_bytes) != 0 ||
        probe_https_target(configuration, "redirector.googlevideo.com", media_request, 512,
                           &media_ms, &media_bytes) != 0) {
        return 1;
    }
    printf("youtube_ok=1 latency_ms=%ld page_ms=%ld media_ms=%ld page_bytes=%lu media_bytes=%lu video_id=cQk4Uw77siY media_host=redirector.googlevideo.com\n",
           page_ms + media_ms, page_ms, media_ms,
           (unsigned long)page_bytes, (unsigned long)media_bytes);
    return 0;
}

static void print_usage(const char *program)
{
    fprintf(stderr, "usage: %s --version | --resolve-a HOST CA_FILE | --fetch-crunch URL_FILE IP OUTPUT CA_FILE | --check-config FILE | --probe-endpoint-config FILE | --probe-config FILE | --probe-youtube-config FILE | --serve FILE\n", program);
}

int main(int argc, char **argv)
{
    struct config configuration;
    char error[256];

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("n300vless %s\n", N300VLESS_VERSION);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--resolve-a") == 0) {
        return resolve_a_doh(argv[2], argv[3]);
    }
    if (argc == 6 && strcmp(argv[1], "--fetch-crunch") == 0) {
        return fetch_crunch_subscription(argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc == 3 && strcmp(argv[1], "--check-config") == 0) {
        if (load_config(argv[2], &configuration, error, sizeof(error)) != 0) {
            fprintf(stderr, "configuration error: %s\n", error);
            return 1;
        }
        printf("configuration ok: transport=%s tls=%d reality=%d vision=%d socks=%s:%d redirect=%s:%d max_clients=%d\n",
               configuration.transport,
               configuration.use_tls,
               configuration.use_reality,
               configuration.use_vision,
               configuration.socks_listen,
               configuration.socks_port,
               configuration.redirect_listen,
               configuration.redirect_port,
               configuration.max_clients);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--probe-config") == 0) {
        if (load_config(argv[2], &configuration, error, sizeof(error)) != 0) {
            fprintf(stderr, "configuration error: %s\n", error);
            return 1;
        }
        return probe_config(&configuration);
    }
    if (argc == 3 && strcmp(argv[1], "--probe-endpoint-config") == 0) {
        if (load_config(argv[2], &configuration, error, sizeof(error)) != 0) {
            fprintf(stderr, "configuration error: %s\n", error);
            return 1;
        }
        return probe_endpoint_config(&configuration);
    }
    if (argc == 3 && strcmp(argv[1], "--probe-youtube-config") == 0) {
        if (load_config(argv[2], &configuration, error, sizeof(error)) != 0) {
            fprintf(stderr, "configuration error: %s\n", error);
            return 1;
        }
        return probe_youtube_config(&configuration);
    }
    if (argc == 3 && strcmp(argv[1], "--serve") == 0) {
        if (load_config(argv[2], &configuration, error, sizeof(error)) != 0) {
            fprintf(stderr, "configuration error: %s\n", error);
            return 1;
        }
        return serve(&configuration);
    }
    print_usage(argv[0]);
    return 2;
}
