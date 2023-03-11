/*
 * @file        aesdserver.c
 * 
 * @brief       Code for socket communication (stream server)
 * 
 * @author      Ritika Ramchandani <rira3427@colorado.edu>
 * @date        Feb 21, 2023
 * 
 * @References  Beej's Guide to Network Programming
 *              Coursera videos for AESD (Weeks 4 and 5)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
#include <sys/queue.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#define PORT ("9000")

#define BACKLOG (10)

#define PATH_SOCKETDATA_FILE ("/var/tmp/aesdsocketdata")

#define RX_PACKET_LEN (100)

#define TIMESTAMP_LEN (100)

#define SLIST_FOREACH_SAFE(var, head, field, tvar)                           \
    for ((var) = SLIST_FIRST((head));                                        \
            (var) && ((tvar) = SLIST_NEXT((var), field), 1);                 \
            (var) = (tvar))


// Struct to hold status flags
typedef struct
{
    bool is_file_open;
    bool is_log_open;
    bool is_socket_open;
    bool signal_caught;
    bool err_detected;
} status_flags;


// Struct to hold values specific to threads
typedef struct
{
    pthread_t tid;
    bool thread_complete;
    int client_fd;
    char ip_str[INET6_ADDRSTRLEN];
} thread_param_t;


int socketfd, socketFile_fd, clientfd;
timer_t timer_id;
int bytes_in_file = 0;
SLIST_HEAD(slisthead, slist_data_s) head; // Head of the linked list
pthread_mutex_t socketFileMutex = PTHREAD_MUTEX_INITIALIZER; // Mutex to control access to socket file

// Flags to control program flow
status_flags s_flags = {.is_file_open = false, .is_log_open = false, .is_socket_open = false, .signal_caught = false, .err_detected = false};

// SLIST struct declaration
typedef struct slist_data_s
{
    thread_param_t thread_param;
    SLIST_ENTRY(slist_data_s) entries;
} slist_data_t;


// Reference from AESD repo for Lecture 9 
// *Result = *ts_1 + *ts_2
static inline void timespec_add( struct timespec *result,
                        const struct timespec *ts_1, const struct timespec *ts_2)
{
    result->tv_sec = ts_1->tv_sec + ts_2->tv_sec;
    result->tv_nsec = ts_1->tv_nsec + ts_2->tv_nsec;
    if( result->tv_nsec > 1000000000L ) {
        result->tv_nsec -= 1000000000L;
        result->tv_sec ++;
    }
}


/*
 * @func        get_in_addr()
 *
 * @brief       Gets socket address from IPv4/IPv6
 *
 * @parameters  Pointer to struct sockaddr
 *
 * @returns     void pointer containing the address
 * 
 * @ref         Code referenced from Beej's Guide to Network Programming
 */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


/*
 * @func        alarm_handler()
 *
 * @brief       Function motified when timer expires
 *
 * @parameters  signal value
 *
 * @returns     void
 * 
 * @ref         Code referenced from repo linked in AESD Lecture 9 
 */
static void alarm_handler(union sigval sigval)
{
    syslog(LOG_INFO, "Caught SIGALARM\n");

    char timestamp[TIMESTAMP_LEN];
    time_t time_since_epoch;
    struct tm broken_time; 
    int ret_bytes, status, bytes_written;

    // Get fd for exclusive access to file
    int file_handle = (int)sigval.sival_int;

    // Get time since epoch and convert into type struct *tm
    time(&time_since_epoch);
    localtime_r(&time_since_epoch, &broken_time); // signal-safe

    // Extract time in the required format
    ret_bytes = strftime(timestamp, TIMESTAMP_LEN, "timestamp:%Y %b %d, %a, %H:%M:%S%n", &broken_time);

    if(ret_bytes == 0)
    {
        syslog(LOG_ERR, "ERROR(): strftime(). Contens undefined");
    }

    // Lock access to the file
    status = pthread_mutex_lock(&socketFileMutex);

    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: pthread_mutex_lock() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }
    
    // Write out timestamp to the file
    bytes_written = write(file_handle, timestamp, ret_bytes);

    bytes_in_file += bytes_written;

    // Unlock mutex
    status = pthread_mutex_unlock(&socketFileMutex);

    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: pthread_mutex_unlock() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }

    if(bytes_written == -1)
    {
        syslog(LOG_ERR, "ERROR: write() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }

}


/*
 * @func        exit_program()
 *
 * @brief       Routine for graceful shutdown
 *
 * @parameters  none
 *
 * @returns     void
 */
static void exit_program()
{
    slist_data_t *t_node, *t_node_temp;
    int status;

    // Delete timer
    status = timer_delete(timer_id);
    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: timer_delete() %s\n", strerror(errno));	
		exit(EXIT_FAILURE);
    }

    // Close log
    if(s_flags.is_log_open)
    {
        closelog();
        s_flags.is_log_open = false;
    }

    // Close file
    if(s_flags.is_file_open)
    {
        close(socketFile_fd);
        s_flags.is_file_open = false;
    }

    // Close socket
    if(s_flags.is_socket_open)
    {
        close(socketfd);
        s_flags.is_socket_open = false;
    }

    // Signal caught
    if(s_flags.signal_caught)
    {
        remove(PATH_SOCKETDATA_FILE);
    }

    while(!SLIST_EMPTY(&head))
    {
        // Join each thread in the linked-list that hasn't been joined already
        SLIST_FOREACH_SAFE(t_node, &head, entries, t_node_temp)
        {
            
            if((status = pthread_join(t_node -> thread_param.tid, NULL)) != 0)
            {
                syslog(LOG_ERR, "ERROR: pthread_join() %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            // Close client fd
            close(t_node -> thread_param.client_fd);

            // Remove the thread from the linked_list once it has been joined
            SLIST_REMOVE(&head, t_node, slist_data_s, entries);

            free(t_node);
        }
        
    }

    // Destroy the mutex that holds access to the socket file
	status = pthread_mutex_destroy(&socketFileMutex);

	if(status != 0)
	{
		syslog(LOG_ERR, "ERROR: pthread_mutex_destroy() %s\n", strerror(errno));	
		exit(EXIT_FAILURE);
	}

}


static void add_timer()
{
    int status; 
    struct sigevent sev;
    struct itimerspec ts;
    struct timespec start_time;

    memset(&sev, 0, sizeof(struct sigevent));
    memset(&ts, 0, sizeof(struct itimerspec));

    sev.sigev_notify = SIGEV_THREAD;

    if(s_flags.is_file_open)
    {
        sev.sigev_value.sival_int = socketFile_fd;
    }
    else
    {
        syslog(LOG_ERR, "Please open socket file before adding timer\n");
    }

    sev.sigev_notify_function = &alarm_handler; // Function to be notified when timer expires

    // Create a timer
    status = timer_create(CLOCK_MONOTONIC, &sev, &timer_id);

    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: timer_create() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }

    // Get current time
    status = clock_gettime(CLOCK_MONOTONIC, &start_time);

    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: clock_gettime() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }
    
    // Re-arm the timer with an interval os 10 seconds
    ts.it_interval.tv_sec = 10;
    ts.it_interval.tv_nsec = 0;

    // Add interval to current value
    timespec_add(&ts.it_value, &start_time, &ts.it_interval);

    // Arm the timer
    status = timer_settime(timer_id, TIMER_ABSTIME, &ts, NULL);

    if(status != 0)
    {
        syslog(LOG_ERR, "ERROR: timer_settime() %s\n", strerror(errno));
        s_flags.err_detected = true;
        return;
    }
}


/*
 * @func        exit_from_thread()
 *
 * @brief       Graceful exit from the thread
 *
 * @parameters  thread parameters and pointer to rx_buffer and rx_packet
 *
 * @returns     void
 * 
 */
static void exit_from_thread(thread_param_t* thread_param, bool free_rx_packet, char* rx_packet, bool free_rx_buf, char* rx_buf)
{
    if(free_rx_packet)
    {
        free(rx_packet);
    }

    if(free_rx_buf)
    {
        free(rx_buf);
    }

    close(thread_param -> client_fd);

    syslog(LOG_INFO, "Closed connection from %s\n", thread_param -> ip_str);

    thread_param -> thread_complete = true;
}


/*
 * @func        signal_handler()
 *
 * @brief       Signal handler called upon signal invocation
 *
 * @parameters  none
 *
 * @returns     void
 * 
 * @ref         Linux System Programming Chapter 10
 */
static void signal_handler(int signo)
{

    // If expected signal is caught, exit gracefully
    if(signo == SIGINT || signo == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting: %s\n", strsignal(signo));
        s_flags.signal_caught = true;

        if(s_flags.is_socket_open)
        {
            if(shutdown(socketfd, SHUT_RDWR) == -1)
	        {
		        syslog(LOG_ERR, "ERROR: shutdown() %s\n", strerror(errno));
	        }
        }
        
    }
    else
    {
        syslog(LOG_ERR, "Unexpected signal caught: %s\n", strsignal(signo));
        s_flags.signal_caught = false;
    }
}


/*
 * @func        server_thread()
 *
 * @brief       Recieves data from each connection and sends it back
 *
 * @parameters  Paramaters specific to each thread
 *
 * @returns     void pointer
 * 
 */
void *server_thread(void* thread_arg)
{
    char* rx_buffer = NULL;
    char* rx_packet = NULL;
    char* newline_offset = NULL;
    int byte_delta_in_file; // bytes written to / read from file
    int num_bytes_change; // bytes to be written to/ to be read from file
    
    int num_bytes_recv, bytes_in_buf = 0;
    int num_buf_segments = 1;
    int status;

    thread_param_t* param = (thread_param_t*) thread_arg;
    
    // Allocate memory to receive and store packets
    rx_packet = (char*) malloc(RX_PACKET_LEN*sizeof(char));

    if(rx_packet == NULL)
    {
        syslog(LOG_ERR, "ERROR: malloc failed for rx_packet\n");
        exit_from_thread(param, false, NULL, false, NULL);
        return NULL;
    }

    rx_buffer = (char*) malloc(RX_PACKET_LEN*sizeof(char)*num_buf_segments);

    if(rx_buffer == NULL)
    {
        syslog(LOG_ERR, "ERROR: malloc failed\n");
        exit_from_thread(param, true, rx_packet, false, NULL);
        return NULL;
    }

    memset(rx_packet, 0, RX_PACKET_LEN);

    // Operate on data stream as long as packets are received 
    while(((num_bytes_recv = recv(param -> client_fd, rx_packet, RX_PACKET_LEN, 0)) > 0) && (!s_flags.signal_caught) && (!s_flags.err_detected))
    {
        
        // If the rx_buffer does not have enough space, realloc it
        if((num_buf_segments*RX_PACKET_LEN) - bytes_in_buf < num_bytes_recv)
        {
            rx_buffer = (char*)realloc(rx_buffer, (++num_buf_segments * RX_PACKET_LEN));

            if(rx_buffer == NULL)
            {
                syslog(LOG_ERR, "ERROR: realloc failed\n");
                exit_from_thread(param, true, rx_packet, false, NULL);
                return NULL;
            }
        }

        // Copy contents of received data packet into storage buffer
        memcpy((void*) (rx_buffer + bytes_in_buf), (void*) rx_packet, num_bytes_recv);
        bytes_in_buf += num_bytes_recv;

        // While packets are complete (newline exists), write out to file
        while((newline_offset = memchr(rx_buffer, (int)'\n', bytes_in_buf)) != NULL)
        {           
            // Number of bytes in the packet
            num_bytes_change = (char*)newline_offset - (char*)rx_buffer + 1;

            if(num_bytes_change < 0)
            {
                syslog(LOG_ERR, "ERROR: Incorrect calculation\n");
            }

            // Lock access to the file
            status = pthread_mutex_lock(&socketFileMutex);

            if(status != 0)
            {
                syslog(LOG_ERR, "ERROR: pthread_mutex_lock() %s\n", strerror(errno));
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }

            // Bytes actually written to file
            byte_delta_in_file = write(socketFile_fd, rx_buffer, num_bytes_change);

            bytes_in_file += byte_delta_in_file;

            // Unlock access to the file
            status = pthread_mutex_unlock(&socketFileMutex);

            if(status != 0)
            {
                syslog(LOG_ERR, "ERROR: pthread_mutex_unlock() %s\n", strerror(errno));
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }

            if(byte_delta_in_file == -1)
            {
                syslog(LOG_ERR, "ERROR: write() %s\n", strerror(errno));
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }
            else if(byte_delta_in_file < num_bytes_change)
            {
                syslog(LOG_ERR, "All bytes have not been written\n");
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }


            bytes_in_buf -= ((char*)newline_offset - (char*)rx_buffer + 1);

            // After writing out bytes to file, shift the bytes to fill the emptied space in the buffer
            memcpy((void*)rx_buffer, (void*)newline_offset, (RX_PACKET_LEN * num_buf_segments) - ((char*)newline_offset - (char*)rx_buffer + 1));
            memset(rx_buffer + bytes_in_buf, 0, (RX_PACKET_LEN * num_buf_segments) - bytes_in_buf);

            // Buffer to read into and send to client from
            char tx_buffer[RX_PACKET_LEN];

            // Bytes to read from file
            num_bytes_change = bytes_in_file;

            // Lock access to the file
            status = pthread_mutex_lock(&socketFileMutex);

            if(status != 0)
            {
                syslog(LOG_ERR, "ERROR: pthread_mutex_lock() %s\n", strerror(errno));
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }

            // Start reading from the beginning of the file
            lseek(socketFile_fd, 0, SEEK_SET);

            // While there are bytes to read from the file, send to server
            while(num_bytes_change != 0)
            {
                byte_delta_in_file = read(socketFile_fd, &tx_buffer[0], RX_PACKET_LEN);

                if(byte_delta_in_file == -1)
                {
                    syslog(LOG_ERR, "ERROR: read()\n");
                    exit_from_thread(param, true, rx_packet, true, rx_buffer);

                    // Unlock access to the file
                    status = pthread_mutex_unlock(&socketFileMutex);

                    if(status != 0)
                    {
                        syslog(LOG_ERR, "ERROR: pthread_mutex_unlock() %s\n", strerror(errno));
                        exit_from_thread(param, true, rx_packet, true, rx_buffer);
                        return NULL;
                    }
                    return NULL;
                }

                int num_bytes_to_send = byte_delta_in_file;

                int total_bytes_sent = 0;

                total_bytes_sent = send(param -> client_fd, &tx_buffer[0], num_bytes_to_send, 0);
                num_bytes_change -= total_bytes_sent;
            } 

            // Unlock access to the file
            status = pthread_mutex_unlock(&socketFileMutex);

            if(status != 0)
            {
                syslog(LOG_ERR, "ERROR: pthread_mutex_unlock() %s\n", strerror(errno));
                exit_from_thread(param, true, rx_packet, true, rx_buffer);
                return NULL;
            }

            newline_offset = NULL;

        } // While newline exists in buffer

        memset(rx_packet, 0, RX_PACKET_LEN);

    } // while data is being received 


    if(num_bytes_recv == -1)
    {
        syslog(LOG_ERR, "ERROR: recv() %s\n", strerror(errno));
    }

    exit_from_thread(param, true, rx_packet, true, rx_buffer);

    return NULL;
}


/*
 * @func        socket_server()
 *
 * @brief       Routine to accept connections and spawn threads
 *
 * @parameters  none
 *
 * @returns     int - status
 * 
 * @ref         Beej's Guide to Network Programming
 */
static int socket_server()
{
    int status; 
    
    struct sockaddr_storage client_addr;
    socklen_t addr_size;
    char ip_str[INET6_ADDRSTRLEN];

    slist_data_t *t_node = NULL;

    SLIST_INIT(&head);
    

    // Listen for connections on the socket
    status = listen(socketfd, BACKLOG);
    if(status == -1)
    {
        syslog(LOG_ERR, "ERROR: listen() %s\n", strerror(errno));
        return -1;
    }


    addr_size = sizeof client_addr;

    // Continue accepting connections till SIGTERM/SIGINT are caught
    while(!s_flags.signal_caught && !s_flags.err_detected)
    {
        // Accept connections
        clientfd = accept(socketfd, (struct sockaddr*)&client_addr, &addr_size);

        // If signal was received, accept will return an error
        if(s_flags.signal_caught || s_flags.err_detected)
        {
            break;
        }

        if(clientfd == -1)
        {
            syslog(LOG_ERR, "ERROR: accept() %s\n", strerror(errno));
            s_flags.err_detected = true;
            return -1;
        }
        else // Print IP address of client
        {
            inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), ip_str, sizeof(ip_str));
            syslog(LOG_INFO, "Accepted connection from %s\n", ip_str);
        }

        // Initialize thread parameters
        t_node = malloc(sizeof(slist_data_t));
        t_node -> thread_param.thread_complete = false;
        t_node -> thread_param.client_fd = clientfd;
        memcpy(t_node -> thread_param.ip_str, ip_str, INET6_ADDRSTRLEN);

        status = pthread_create(&t_node -> thread_param.tid, NULL, server_thread, (&(t_node -> thread_param)));

        if(status == -1)
        {
            syslog(LOG_ERR, "ERROR: pthread_create() %s\n", strerror(errno));

            s_flags.err_detected = true;
        }

        // Insert the thread node into the linked list
        SLIST_INSERT_HEAD(&head, t_node, entries);

        slist_data_t *t_node_temp = NULL;

        // If the thread is complete, join it
        SLIST_FOREACH_SAFE(t_node, &head, entries, t_node_temp)
        {
            if(t_node -> thread_param.thread_complete)
            {
                if((status = pthread_join(t_node -> thread_param.tid, NULL)) != 0)
                {
                    syslog(LOG_ERR, "ERROR: pthread_join() %s\n", strerror(errno));

                    s_flags.err_detected = true;
                }

                // Close client fd
                close(t_node -> thread_param.client_fd);

                // Remove the thread from the linked_list once it has been joined
                SLIST_REMOVE(&head, t_node, slist_data_s, entries);

                free(t_node); // Free the thread node
            }
        }
    }

    close(socketfd);
    s_flags.is_socket_open = false;

    return 0;
}


int main(int argc, char* argv[])
{
    int ret_val;
    struct addrinfo hints, *res;
    int status;
    int opt_val = 1;
    bool daemon_mode = false;

    // Signal initialization
    if((signal(SIGINT, signal_handler) == SIG_ERR) || (signal(SIGTERM, signal_handler) == SIG_ERR)) 
    {
        syslog(LOG_ERR, "ERROR: signal() %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Adding support for running daemon
    if((argc == 2))
    {
        if(strcmp(argv[1], "-d") == 0)
        {
            syslog(LOG_INFO, "Starting in Daemon mode\n");
            daemon_mode = true;
        }
        else
        {
            syslog(LOG_ERR, "Invalid argument passed. \"-d\" expcted\n");
            return -1;
        }
    }
    else if(argc > 2)
    {
        syslog(LOG_ERR, "ERROR: Invalid number of arguments passed. Expected = 2, passed = %d\n", argc);
    }

    // Open system log for logging capability
    openlog(NULL, LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);
    s_flags.is_log_open = true;

    // Create file to write into
    socketFile_fd = open(PATH_SOCKETDATA_FILE, O_CREAT | O_APPEND | O_RDWR, 0744);

    
    if(socketFile_fd == -1)
    {
        syslog(LOG_ERR, "ERROR: open() %s\n", strerror(errno));
        exit_program();
        return -1;
    }

    syslog(LOG_INFO, "File opened\n");
    s_flags.is_file_open = true;

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
        exit_program();
        return -1;
    }
    s_flags.is_socket_open = true;

    // To avoid errors from bind()
    status = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(int));

    if(status == -1) 
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
        exit_program();
        return -1;
    }

    // Result is not used anymore
    freeaddrinfo(res);

    
    if(daemon_mode)
    {
        if((status = daemon(0, 0)) == -1)
        {
            syslog(LOG_ERR, "ERROR: fork() %s\n", strerror(errno));
            exit_program();
            return -1;
        }
    }

    // Initialize timer
    add_timer();

    ret_val = socket_server();
    
    exit_program(); // Clean exit

    return ret_val;
}

