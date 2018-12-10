if [ $# -eq 0 ]
then
        LIBGNUTLS="libgnutls.so.[3-9][0-9]"
        # >= libgnutls.so.30 - 3.6.4
        if [ -d "/usr/include/gnutls" ];then
                # .pc are not available for all libs!!
                #pkg-config --exists --print-errors "gnutls >= 3.6.4"
                #if [ $? -eq 0 ];then exit 0;else exit 1;fi
		uname | grep "Linux" > /dev/null
		if [ $? -lt 1 ]
		then
	        	/sbin/ldconfig -p|grep "$LIBGNUTLS" > /dev/null
		else
                        ls -las /usr/lib64/libgnutls.so* || ls -las /usr/lib/libgnutls.so* 2>&1|grep "$LIBGNUTLS" > /dev/null
		fi
                if [ $? -eq 0 ];then echo "gnutls";else echo "";fi
        else
                echo ""
        fi
elif [ "$1" = "gnutls" ] 
then
        if [ "$2" = "-d" ] 
	then
	       echo "-D TLSPROTOCOL"
	elif [ "$2" = "-c" ]
	then
		echo "SafedTLS.o"
	elif [ "$2" = "-l" ]
 	then
		echo "-lgnutls"
	else
		echo ""
	fi
else
	echo ""
fi
