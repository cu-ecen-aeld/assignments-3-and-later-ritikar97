#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

/// Logging errors and debug statements
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

// Scaling factor for conversion from ms to us
#define MS_TO_US_SCALING (1000)

/*
 * @brief   Check for error and print error message
 * 
 * @input   ret_val - Value returned by system call
 * @input   msg - Error message for debug
 * 
 * @returns 1 on error and 0 on success
 */
static int err_check(int ret_val, char* msg)
{
    if(ret_val != 0)
    {
        errno = ret_val;
        ERROR_LOG("ERROR: %s %s\n", msg, strerror(errno));
        return 1;
    }
    return 0;
}

/*
 * @brief   Wait, obtain mutex, wait, release mutex as described by thread_data structure
 * 
 * @input   void pointer pointing to the thread data structure
 * 
 * @returns void pointer pointer to the thread data structure
 */
void* threadfunc(void* thread_param)
{
    int ret_val;

    // Casting void pointer into a pointer of type thread_data*
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // Checking if pointer to mutex is NULL
    if(thread_func_args -> mutex == NULL)
    {
        ERROR_LOG("ERROR: Pthread mutex points to NULL\n");
        return thread_param;
    }


    // Checking for invalid values of wait to obtain/release
    if((thread_func_args -> wait_to_obtain_ms < 0) || (thread_func_args -> wait_to_release_ms < 0))
    {
        DEBUG_LOG("Wait time to obtain mutex = %d\n", thread_func_args -> wait_to_obtain_ms);
        DEBUG_LOG("Wait time to release mutex = %d\n", thread_func_args -> wait_to_release_ms);
        ERROR_LOG("ERROR: Wait time to obtain/release mutex is invalid. Must be 0 or greater\n");
        return thread_param;
    }


    // Non-blocking call to sleep before obtaining mutex
    ret_val = usleep(thread_func_args -> wait_to_obtain_ms * MS_TO_US_SCALING);
    if(err_check(ret_val, "usleep() failed with error:"))
    {
        return thread_param;
    }


    // Obtaining the mutex lock
    ret_val = pthread_mutex_lock(thread_func_args -> mutex);
    if(err_check(ret_val, "Mutex could not be locked:"))
    {
        return thread_param;
    }

    DEBUG_LOG("Successfully locked mutex\n");


    // Non-blocking call to sleep before releasing mutex
    ret_val = usleep(thread_func_args -> wait_to_release_ms * MS_TO_US_SCALING);
    if(err_check(ret_val, "usleep() failed with error:"))
    {
        return thread_param;
    }


    // Releasing mutex lock
    ret_val = pthread_mutex_unlock(thread_func_args -> mutex);
    if(err_check(ret_val, "Mutex could not be unlocked:"))
    {
        return thread_param;
    }
    
    DEBUG_LOG("Successfully unlocked mutex\n");

    thread_func_args -> thread_complete_success = true;

    return (void*) thread_func_args;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * Allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    int ret;

    struct thread_data* t_data = (struct thread_data*) malloc(sizeof(struct thread_data*));

    // Malloc check
    if(t_data == NULL)
    {
        ERROR_LOG("ERROR: Malloc failed for sturct thread_data");
        return false;
    }

    // Assigning values to the thread data structure
    t_data -> wait_to_obtain_ms = wait_to_obtain_ms;
    t_data -> wait_to_release_ms = wait_to_release_ms;
    t_data -> mutex = mutex;
    t_data ->thread_complete_success = false;

    ret = pthread_create(thread, NULL, threadfunc, (void *) t_data);

    if(err_check(ret, "Pthread could not be created with error"))
    {
        return false;
    }


    DEBUG_LOG("Thread creation complete\n");

    return true;
}

