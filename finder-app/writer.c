/*
 * @file        writer.c
 * 
 * @brief       This code creates a new file and writes the specified content into the file. 
 *              It overwrites any exiting file with the new content.
 * 
 * @author      Ritika Ramchandani <rira3427@colorado.edu>
 * @date        Jan 28, 2023
 * 
 * @References  Linux System Programming by Robet Love, Chapter 2
 *              Coursera Week 2 videos for AESD 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>


/* Macro for number of arguments required by writer.c */
#define WRITER_ARGS_N   (3)


/*
 * @brief   Function to open a file and write to it
 * 
 * @input   filename - Name of the file to be written to
 * @input   str - String to write into the file
 * 
 * @output  void
 */
static void write_to_file(const char* filename, const char* str);



/* Main function */
int main(int argc, char **argv)
{
    
    /* Open system log for logging capability */
    openlog("ErrorLog", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);
    
    /* Check for correct number of input arguments */
    if(argc != WRITER_ARGS_N)
    {
        syslog(LOG_ERR, "Invalid number of input arguments to program write.c\n");

        printf("Number of arguments expected is %d and number of arguments provided is %d\n", WRITER_ARGS_N, argc);
        printf("Arguments expected: filename, content to write to file\n");

        exit(1);
    }

    /* Fucntion to write to the file */
    write_to_file(argv[1], argv[2]);

    /* Close system log */
    closelog();

    return 0;

}


static void write_to_file(const char* filename, const char* str)
{
    ssize_t bytes_n; /* to track number of bytes written */
    int len = strlen(str);
    
    /* Create/open file with rwx permissions to user and group, and read-only permissions to others */
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IROTH);

    /* If file could not be opened, log error and exit*/
    if(fd == -1)
    {
        syslog(LOG_ERR, "Error opening %s, errno is %d\n", filename, errno);
        exit(1);
    }
    else
    {
        bytes_n = write(fd, str, strlen(str));

        /* Report errno code for -1 */
        if(bytes_n == -1)
        {
            syslog(LOG_ERR, "Error writing to file \"%s\" with errno %d\n", filename, errno);
        }
        else if(bytes_n != len) /* Possible error but errno code is not reported if byntes_n != -1 */
        {
            syslog(LOG_ERR, "Error writing to file \"%s\". Number of bytes written = %ld\n", filename, bytes_n);
        }
        else /* Log successful write */
        {
            syslog(LOG_DEBUG, "Writing \"%s\" to file \"%s\"\n", str, filename);
        }

        /* Close the file */
        close(fd);
    }
}

