#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

#define MS_TO_US_SCALING (1000)

void* threadfunc(void* thread_param)
{
    int ret_val;
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    if(thread_func_args -> mutex == NULL)
    {
        ERROR_LOG("ERROR: Pthread mutex points to NULL\n");
        return thread_param;
    }

    if((thread_func_args -> wait_to_obtain_ms < 0) || (thread_func_args -> wait_to_release_ms < 0))
    {
        DEBUG_LOG("Wait time to obtain mutex = %d\n", thread_func_args -> wait_to_obtain_ms);
        DEBUG_LOG("Wait time to release mutex = %d\n", thread_func_args -> wait_to_release_ms);
        ERROR_LOG("ERROR: Wait time to obtain/release mutex is invalid. Must be 0 or greater\n");
        return thread_param;
    }

    ret_val = usleep(thread_func_args -> wait_to_obtain_ms * MS_TO_US_SCALING);

    if(ret_val != 0)
    {
        errno = ret_val;
        ERROR_LOG("ERROR: usleep() failed with error: %s\n", strerror(errno));
        return thread_param;
    }

    ret_val = pthread_mutex_lock(thread_func_args -> mutex);

    if(ret_val != 0)
    {
        errno = ret_val;
        ERROR_LOG("ERROR: Mutex could not be locked: %s\n", strerror(errno));
        return thread_param;
    }
    else
    {
        DEBUG_LOG("Successfully locked mutex\n");
    }

    ret_val = usleep(thread_func_args -> wait_to_release_ms * MS_TO_US_SCALING);

    if(ret_val != 0)
    {
        errno = ret_val;
        ERROR_LOG("ERROR: usleep() failed with error: %s\n", strerror(errno));
        return thread_param;
    }

    ret_val = pthread_mutex_unlock(thread_func_args -> mutex);

    if(ret_val != 0)
    {
        errno = ret_val;
        ERROR_LOG("ERROR: Mutex could not be unlocked: %s\n", strerror(errno));
        return thread_param;
    }
    else
    {
        DEBUG_LOG("Successfully unlocked mutex\n");
    }

    thread_func_args -> thread_complete_success = true;

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    return (void*) thread_func_args;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    int ret;

    struct thread_data* t_data = (struct thread_data*) malloc(sizeof(struct thread_data*));

    /* Malloc check */
    if(t_data == NULL)
    {
        ERROR_LOG("ERROR: Malloc failed for sturct thread_data");
        return false;
    }

    t_data -> wait_to_obtain_ms = wait_to_obtain_ms;
    t_data -> wait_to_release_ms = wait_to_release_ms;
    t_data -> mutex = mutex;
    t_data ->thread_complete_success = false;

    ret = pthread_create(thread, NULL, threadfunc, (void *) t_data);

    if(ret != 0)
    {
        errno = ret;
        ERROR_LOG("ERROR: Pthread could not be created with error %s\n", strerror(errno));
        return false;
    }
    
    DEBUG_LOG("Thread creation complete\n");

    return true;
}

