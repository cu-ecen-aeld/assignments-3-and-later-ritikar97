#!/bin/bash

# file: finder.sh
# This script checks for a given string within a given filesystem

#Input arguments
filesdir=$1
searchstr=$2

# Checking for a valid number of arguments
if [ $# -ne 2 ]
then
    echo "Invalid number of arguments"
    exit 1

# Checking whether the given file directory exists 
elif [ -d "$filesdir" ]
then 

    # Counting number of lines that have the string
    lines_n=$(grep -r ${searchstr} ${filesdir} | wc -l)

    # Counting number of files that have the string
    files_n=$(grep -lr ${searchstr} ${filesdir} | wc -l)
    
    echo "The number of files are $files_n and the number of matching lines are $lines_n"
    exit 0

# Error printed in case the path is not found   
else
    echo '$filesdir does not represent a directory in the filesystem'
    exit 1
fi

