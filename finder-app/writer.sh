#!/bin/bash

# file: writer.sh
# This script creates a file at the specified location with the specified text

#Input arguments
writefile=$1
writestr=$2

# Checking for a valid number of arguments
if [ $# -ne 2 ]
then
    echo "Invalid number of arguments"
    exit 1

 
else 

    # Get directory
    dir_path=$(dirname "${writefile}")

    # If directory does not exist, create with parent directories as required
    if [ ! -d "$dir_path" ]
    then
        mkdir -p $dir_path
    fi

    # Write given string into the file
    echo $writestr > $writefile

    # If file was created, exit normally else throw an error
    if [ -f "$writefile" ]
    then
        exit 0
    else
        echo "Error: File could not be created"
        exit 1
    fi

fi

