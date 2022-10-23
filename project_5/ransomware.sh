#!/bin/bash

create () {
    mkdir -p "$1"
    LD_PRELOAD=./logger.so ./test_aclog -D "$1" -n "$2"
}

encrypt () {
    if [ -d $1 ]; then
        for f in $1/*
        do
            LD_PRELOAD=./logger.so openssl enc -aes-256-ecb -in $f -out "$f.encrypt" -k 1234 -a -pbkdf2
            rm $f
        done
    else
        echo "Directory \"$1\" does't exist."
    fi
}

decrypt () {
    if [ -d $1 ]; then
        for f in $1/*
        do
            if [ -f $f ]; then
                openssl aes-256-ecb -d -in $f -out ${f%.encrypt} -k 1234 -a -pbkdf2
                rm $f
            fi
        done
    else
        echo "Directory \"$1\" does't exist."
    fi
}

usage () {
    printf  "Usage: ./ransomware [-D dir|-n num|-h]\n"
    printf  "Options:\n"
    printf -- "-n <num>       the number of files to be created for the ransomware sim\n"
    printf -- "-D <dirname>   the directory in which they will be put\n"
    printf -- "-h             display this help message\n\n"
    exit
}

if test "$#" -eq 0; then
    printf "No arguments were inserted.\n\n"
    usage
    exit
fi

while getopts "D:n:hd:" flag
do
    case "${flag}" in
        D)  dir=${OPTARG};;
        n)  num=${OPTARG};;
        d)  decrypt ${OPTARG}
            exit;;
       \? | h)  usage
            exit ;;
    esac
done

if [ "$dir" = "" ] || [ "$num" = "" ] || test "$num" -lt 1; then
    usage
    exit
fi

create $dir $num;
encrypt $dir;