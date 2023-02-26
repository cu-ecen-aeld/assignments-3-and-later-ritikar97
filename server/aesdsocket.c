/*
 * @file        aesdserver.c
 * 
 * @brief       Code for socket communication (stream server)
 * 
 * @author      Ritika Ramchandani <rira3427@colorado.edu>
 * @date        Feb 21, 2023
 * 
 * @References  Beej's Guide to Network Programming
 *              Coursera Week 4 videos for AESD 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <syslog.h>

#define PORT ("9000")

#define BACKLOG (10)

#define PATH_SOCKETDATA_FILE ("/var/tmp/aesdsocketdata")

#define RX_PACKET_LEN (100)

typedef struct
{
    bool is_file_open;
    bool is_log_open;
    bool is_socket_open;
    bool signal_caught;

} status_flags;

int socketfd, socketFile_fd;

status_flags s_flags = {.is_file_open = false, .is_log_open = false, .is_socket_open = false, .signal_caught = false};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


// Close log, socket, socketFile, delete the file
static void exit_program()
{
    if(s_flags.is_log_open)
    {
        closelog();
    }
    
    if(s_flags.is_file_open)
    {
        close(socketFile_fd);
    }

    if(s_flags.is_socket_open)
    {
        close(socketfd);
    }

    if(s_flags.signal_caught)
    {
        remove(PATH_SOCKETDATA_FILE);
    }

}


// Referenced from Linux System Programming Chapter 10
static void signal_handler(int signo)
{
    if(signo == SIGINT || signo == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting: %s\n", strsignal(signo));
        s_flags.signal_caught = true;
        exit_program();
        exit(EXIT_SUCCESS);
    }
    else
    {
        syslog(LOG_ERR, "Unexpected signal caught: %s\n", strsignal(signo));
        s_flags.signal_caught = false;
    }
}


static int socket_server()
{
    int status, num_bytes_recv, bytes_in_buf = 0;
    int num_buf_segments = 1;
    int byte_delta_in_file; // bytes written to / read from file
    int num_bytes_change; // bytes to be written to/ to be read from file
    int bytes_in_file = 0;
    int clientfd;
    struct sockaddr_storage client_addr;
    socklen_t addr_size;
    char ip_str[INET6_ADDRSTRLEN];
    char* rx_buffer = NULL;
    char* rx_packet = NULL;
    char* newline_offset = NULL;

    

    // Listen for connections on the socket
    status = listen(socketfd, BACKLOG);
    if(status == -1)
    {
        syslog(LOG_ERR, "ERROR: listen() %s\n", strerror(errno));
        return -1;
    }


    addr_size = sizeof client_addr;

    // Continue accepting connections till SIGTERM/SIGINT are caught
    while(!s_flags.signal_caught)
    {
        // Accept connections
        clientfd = accept(socketfd, (struct sockaddr*)&client_addr, &addr_size);
        if(clientfd == -1)
        {
            syslog(LOG_ERR, "ERROR: accept() %s\n", strerror(errno));
            return -1;
        }
        else // Print IP address of client
        {
            inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), ip_str, sizeof(ip_str));
            syslog(LOG_INFO, "Accepted connection from %s\n", ip_str);
        }


        // Allocate memory to receive and store packets
        rx_packet = (char*) malloc(RX_PACKET_LEN*sizeof(char));
        rx_buffer = (char*) malloc(RX_PACKET_LEN*sizeof(char)*num_buf_segments);

        if(rx_buffer == NULL || rx_packet == NULL)
        {
            syslog(LOG_ERR, "ERROR: malloc failed\n");
            return -1;
        }
        memset(rx_packet, 0, RX_PACKET_LEN);

        // Operate on data stream as long as packets are received 
        while((num_bytes_recv = recv(clientfd, rx_packet, RX_PACKET_LEN, 0)) > 0)
        {

            printf("Just received %s\n", rx_packet);
            // If the rx_buffer does not have enough space, realloc it
            if((num_buf_segments*RX_PACKET_LEN) - bytes_in_buf < num_bytes_recv)
            {
                rx_buffer = (char*)realloc(rx_buffer, (++num_buf_segments * RX_PACKET_LEN));

                if(rx_buffer == NULL)
                {
                    syslog(LOG_ERR, "ERROR: realloc failed\n");
                    return -1;
                }
            }

            memcpy((void*) (rx_buffer + bytes_in_buf), (void*) rx_packet, num_bytes_recv);
            bytes_in_buf += num_bytes_recv;


            while((newline_offset = memchr(rx_buffer, (int)'\n', bytes_in_buf)) != NULL)
            {            
                                num_bytes_change = (char*)newline_offset - (char*)rx_buffer + 1;

                if(num_bytes_change < 0)
                {
                    syslog(LOG_ERR, "ERROR: Incorrect calculation\n");
                }
                
                byte_delta_in_file = write(socketFile_fd, rx_buffer, num_bytes_change);

                if(byte_delta_in_file == -1)
                {
                    printf("Error in write()\n");
                    syslog(LOG_ERR, "ERROR: write() %s\n", strerror(errno));
                    return -1;
                }
                else if(byte_delta_in_file < num_bytes_change)
                {
                    syslog(LOG_ERR, "All bytes have not been written\n");
                    return -1;
                }

                bytes_in_file += byte_delta_in_file;

                bytes_in_buf -= ((char*)newline_offset - (char*)rx_buffer + 1);

                memcpy((void*)rx_buffer, (void*)newline_offset, (RX_PACKET_LEN * num_buf_segments) - ((char*)newline_offset - (char*)rx_buffer + 1));
                memset(rx_buffer + bytes_in_buf, 0, (RX_PACKET_LEN * num_buf_segments) - bytes_in_buf);

                char tx_buffer[RX_PACKET_LEN];

                num_bytes_change = bytes_in_file;

                lseek(socketFile_fd, 0, SEEK_SET);

                while(num_bytes_change != 0)
                {
                    byte_delta_in_file = read(socketFile_fd, &tx_buffer[0], RX_PACKET_LEN);
                    if(byte_delta_in_file == -1)
                    {
                        syslog(LOG_ERR, "ERROR: read()\n");
                        return -1;
                    }

                    int num_bytes_to_send = byte_delta_in_file;

                    int total_bytes_sent = 0;

                    total_bytes_sent = send(clientfd, &tx_buffer[0], num_bytes_to_send, 0);
                    num_bytes_change -= total_bytes_sent;
                } // while there are bytes to read from the file

                newline_offset = NULL;

            } // While newline exists in buffer

            memset(rx_packet, 0, RX_PACKET_LEN);

        } // while data is being received 


        if(num_bytes_recv == -1)
        {
            syslog(LOG_ERR, "ERROR: recv() %s\n", strerror(errno));
            return -1;
        }

        free(rx_buffer);
        free(rx_packet);

        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), ip_str, sizeof(ip_str));
        syslog(LOG_INFO, "Closed connection from %s\n", ip_str);

    }

    close(socketfd);
    s_flags.is_socket_open = false;

    return 0;
}


int main()
{
    int ret_val;
    struct addrinfo hints, *res;
    int status;
    int opt_val = 1;

    // Signal initialization
    if((signal(SIGINT, signal_handler) == SIG_ERR) || (signal(SIGTERM, signal_handler) == SIG_ERR)) 
    {
        syslog(LOG_ERR, "ERROR: signal() %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }


    // Open system log for logging capability
    openlog(NULL, LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);
    s_flags.is_log_open = true;

    // Create file to write into
    socketFile_fd = open(PATH_SOCKETDATA_FILE, O_CREAT | O_APPEND | O_RDWR, S_IRWXU | S_IRGRP | S_IROTH);

    syslog(LOG_INFO, "File opened\n");
    
    if(socketFile_fd == -1)
    {
        syslog(LOG_ERR, "ERROR: open() %s\n", strerror(errno));
        exit_program();
        return -1;
    }

    // Initialize and obtain socket address
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(NULL, PORT, &hints, &res);
    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: getaddrinfo() %s\n", gai_strerror(status));
        exit_program();
        return -1;
    }

    // Open socket
    socketfd = socket(res -> ai_family, res -> ai_socktype, res -> ai_protocol);

    if(socketfd == -1)
    {
        syslog(LOG_ERR, "ERROR: socket() %s\n", strerror(errno));
        return -1;
    }

    s_flags.is_socket_open = true;

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEADDR, &opt_val, sizeof(int)) == -1) 
    {
        syslog(LOG_ERR, "ERROR: setsockopt()) %s\n", gai_strerror(status));
        exit_program();
        return -1;
    }

    // Bind the socket to an address
    status = bind(socketfd, res -> ai_addr, res -> ai_addrlen);

    if(status == -1)
    {
        syslog(LOG_ERR, "ERROR: bind() %s\n", strerror(errno));
        return -1;
    }

    // Result is not used anymore
    freeaddrinfo(res);

    ret_val = socket_server();
    
    exit_program();

    return ret_val;
}

