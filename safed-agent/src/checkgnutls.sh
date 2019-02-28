if [ $# -eq 0 ]
then
        LIBWOLFTLS="libwolfssl.so.19"
        # >= libwolfssl.so.19.0.0 
        for d in /usr/lib64/ /usr/lib/ /lib /lib64 /usr/local/lib /usr/local/lib64
        do 
            if [ -d $d ]; then 
                find $d |grep -E "$LIBWOLFTLS" > /dev/null
                if [ $? -eq 0 ];then echo "wolfssl"; exit 0;fi
            fi
        done
        echo ""    
elif [ "$1" = "wolfssl" ] 
then
        if [ "$2" = "-d" ] 
	then
	       echo "-I../external/wolfssl/wolfssl/ -DTLSPROTOCOL -DWC_RSA_BLINDING -DWOLFSSL_TLS13"
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
