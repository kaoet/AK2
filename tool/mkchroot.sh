#!/bin/bash

CHROOT="/var/chroot"

copy_directory(){
    FILE_LOCATION="$1"
    if ! [ -d "$FILE_LOCATION" ]; then
        echo Cannot find $FILE_LOCATION! Ignore.
    fi
    echo Copying directory $FILE_LOCATION
    FILE_DIR=`dirname "$FILE_LOCATION"`
    mkdir -p "$CHROOT/$FILE_DIR"
    cp -r "$FILE_LOCATION" "$CHROOT/$FILE_DIR"
}
copy_file(){
    FILE_LOCATION="$1"
	if [[ -z "$2" ]]; then
		DEST_LOCATION="$1"
	else
		DEST_LOCATION="$2"
	fi
    if ! [ -e "$FILE_LOCATION" ]; then
        echo Cannot find $FILE_LOCATION! Ignore.
    fi
    echo Copying $FILE_LOCATION
    DEST_DIR=`dirname "$DEST_LOCATION"`
    mkdir -p "$CHROOT/$DEST_DIR"
    cp "$FILE_LOCATION" "$CHROOT/$DEST_LOCATION"
}

copy_lib(){
	LIB_NAME="$1"
	LIB_LOCATIONS=`locate "/$LIB_NAME"`
	if [ $? -ne 0 ]; then
		echo "Cannot find $LIB_NAME! Ignore."
        return
    fi
    IFS=$'\n'
    for LIB_LOCATION in `locate "/$LIB_NAME"`; do
        copy_file "$LIB_LOCATION"
    done
    unset IFS
}

if [ "root" != `whoami` ]; then
    echo Please sudo me!
    exit
fi

rm -rf $CHROOT
if [ -e "$CHROOT" ]; then
    echo "$CHROOT existed. Please do rm -rf $CHROOT."
    exit
fi

mkdir -p "$CHROOT"

# make /dev
mkdir -p "$CHROOT/dev"
mknod -m 666 "$CHROOT/dev/null" c 1 3

# required libraries
copy_lib "libc.so"
copy_lib "libtinfo.so"
copy_lib "libz.so"
copy_lib "libm.so"
copy_lib "ld-linux-x86-64.so"
copy_lib "libdl.so"
copy_lib "libmpc.so"
copy_lib "libgmp.so"
copy_lib "libmpfr.so"
copy_lib "libpthread.so"
copy_lib "libutil.so"
copy_lib "libcrypto.so"
copy_lib "libstdc++.so"
copy_lib "libssl.so"
copy_lib "libopcodes-"
copy_lib "libbfd-"
copy_lib "libcloog-isl.so"
copy_lib "libisl.so"
copy_lib "crt1.o"
copy_lib "crti.o"
copy_lib "crtn.o"
copy_lib "libgcc_s.so"
copy_lib "libc_nonshared.a"

# copy shell utils
copy_file "/bin/bash"
copy_file "/bin/busybox"

# copy headers
copy_directory "/usr/include"

# copy GCC
copy_file "/usr/bin/as"
copy_file "/usr/bin/ld"
copy_file "/usr/bin/gcc"
copy_file "/usr/bin/g++"
copy_directory "/usr/lib/gcc"

# copy python
for PY_VER in 9 8 7 6 5 4 3 2 1; do
	if [ -e /usr/bin/python2.$PY_VER ]; then
		copy_file "/usr/bin/python2.$PY_VER" "/usr/bin/python2"
		copy_directory "/usr/lib/python2.$PY_VER"
		break
    fi
done
for PY_VER in 9 8 7 6 5 4 3 2 1; do
	if [ -e /usr/bin/python3.$PY_VER ]; then
		copy_file "/usr/bin/python3.$PY_VER" "/usr/bin/python3"
		copy_directory "/usr/lib/python3.$PY_VER"
		break
	fi
done

# copy fpc
copy_file "/usr/bin/fpc"
copy_file "/usr/bin/ppcx64"
copy_directory "/usr/lib/fpc"

# example files
echo "#include <stdio.h>" >$CHROOT/main.c
echo "int main(){" >> $CHROOT/main.c
echo "  int x,y;" >> $CHROOT/main.c
echo "  scanf(\"%i%i\",&x,&y);" >> $CHROOT/main.c
echo "  printf(\"%i\\n\",x+y);" >> $CHROOT/main.c
echo "  return 0;" >> $CHROOT/main.c
echo "}" >> $CHROOT/main.c

echo "#include <iostream>" >$CHROOT/main.cpp
echo "using namespace std;" >>$CHROOT/main.cpp
echo "int main(){" >> $CHROOT/main.cpp
echo "  int x,y;" >> $CHROOT/main.cpp
echo "  cin>>x>>y;" >> $CHROOT/main.cpp
echo "  cout<<x+y<<endl;" >> $CHROOT/main.cpp
echo "  return 0;" >> $CHROOT/main.cpp
echo "}" >> $CHROOT/main.cpp

echo "print sum([int(x) for x in raw_input().split(' ')]);" >$CHROOT/main.py

echo "uses math;" > $CHROOT/main.pas
echo "var" >> $CHROOT/main.pas
echo "  a,b:longint;" >> $CHROOT/main.pas
echo "begin" >> $CHROOT/main.pas
echo "  read(a,b);" >> $CHROOT/main.pas
echo "  writeln(max(a,b));" >> $CHROOT/main.pas
echo "end." >> $CHROOT/main.pas
