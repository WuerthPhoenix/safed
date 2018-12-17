if [ $# -eq 0 ]
then
        LIBGNUTLS="libgnutls.so.((3[0-9].[2-9][0-9])|([4-9][0-9]))"
        # >= libgnutls.so.30.22 - 3.6.4
        if [ -d "/usr/include/gnutls" ];then
                # .pc are not available for all libs!!
                #pkg-config --exists --print-errors "gnutls >= 3.6.4"
                #if [ $? -eq 0 ];then exit 0;else exit 1;fi
                for d in /usr/lib64/ /usr/lib/ /lib /lib64
                do  
                    find $d |grep -E "$LIBGNUTLS" > /dev/null
                    if [ $? -eq 0 ];then echo "gnutls"; exit 0;fi
                done
                echo ""    
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
