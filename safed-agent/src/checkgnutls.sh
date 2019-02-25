if [ $# -eq 0 ]
then
        LIBWOLFTLS="libwolfssl.so.19"
        # >= libwolfssl.so.19.0.0 
        if [ -d "/usr/include/wolfssl" ];then
                # .pc are not available for all libs!!
                #pkg-config --exists --print-errors "gnutls >= 3.6.4"
                #if [ $? -eq 0 ];then exit 0;else exit 1;fi
                for d in /usr/lib64/ /usr/lib/ /lib /lib64
                do  
                    find $d |grep -E "$LIBWOLFTLS" > /dev/null
                    if [ $? -eq 0 ];then echo "wolfssl"; exit 0;fi
                done
                echo ""    
        else
                echo ""
        fi
elif [ "$1" = "wolfssl" ] 
then
        if [ "$2" = "-d" ] 
	then
	       echo "-D TLSPROTOCOL -DWC_RSA_BLINDING"
	elif [ "$2" = "-c" ]
	then
		echo "SafedTLS.o"
	elif [ "$2" = "-l" ]
 	then
		echo "-lwolfssl"
	else
		echo ""
	fi
else
	echo ""
fi
