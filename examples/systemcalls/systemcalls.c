#include "systemcalls.h"
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> 
#include <sys/wait.h>


/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int ret = system(cmd);

    // Error occured or non-zero value was returned by the command
    if(ret == -1 || ret != 0) 
        return false;

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    pid_t pid, wait_pid;
    int status;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;


/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/

    // Forking the child and testing error condition
    pid = fork();

    if(pid == -1)
    {
        printf("Error occured while forking a process with errno %d\n", errno);
        return false;
    }
    
    // If child process, exec command
    if(pid == 0)
    {
        int ret;
        ret = execv(command[0], command);

        // Error testing
        if(ret == -1)
        {
            perror("Eror executing the program with execv()");
            exit(1);
        }
    }
    
    // If parent process, wait for child to terminate
    if(pid > 0)
    {
        wait_pid = wait(&status);

        // Error testing
        if (wait_pid == -1)
        {
            perror ("Error with wait()");
            return false;

        }
        else
        {
            // Check if child exited normally
            if(WIFEXITED(status))
            {
                // Check if child process exited with return value 0
                if(WEXITSTATUS(status) != 0)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

        }
    }

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    int fd;
    pid_t pid, wait_pid;
    int status;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;



/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
    // Opening the output file
    fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    // Error checking for opening file
    if (fd < 0) 
    { 
        perror("Error opening file"); 
        return false; 
    }

    // Forking the child and testing error condition
    pid = fork();

    if(pid == -1)
    {
        printf("Error occured while forking a process with errno %d\n", errno);
        return false;
    }
    
    // If child process, exec command
    if(pid == 0)
    {
        int ret;

        // Duplicating file descriptor and checking for error
        if (dup2(fd, 1) < 0) 
        { 
            perror("Error with dup2"); 
            close(fd);
            exit(EXIT_FAILURE);
        }


        // Execute command and test error condition
        ret = execv(command[0], command);

        if(ret == -1)
        {
            perror("Eror executing the program with execv()");
            exit(EXIT_FAILURE);
        }
    }
    
    // If parent process, wait for child to terminate
    if(pid > 0)
    {
        //Close file descriptor
        close(fd);

        wait_pid = wait(&status);

        // Error testing
        if (wait_pid == -1)
        {
            perror ("Error with wait()");
            return false;

        }
        else
        {
            // Check if child exited normally
            if(WIFEXITED(status))
            {
                // Check if child exited with a return value 0
                if(WEXITSTATUS(status) != 0)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

        }
    }


    va_end(args);

    return true;
}
