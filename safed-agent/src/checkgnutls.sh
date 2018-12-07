if [ $# -eq 0 ]
then
        if [ -d "/usr/include/gnutls" ];then 
                pkg-config --exists --print-errors "gnutls >= 3.6.4"
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
