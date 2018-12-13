#include <string.h>
#include <stdlib.h>


int hex2int(char *pChars)
{
	int Hi;
	int Lo;
	int Result;

	Hi = pChars[0];
	if ('0' <= Hi && Hi <= '9') {
		Hi -= '0';
	} else if ('a' <= Hi && Hi <= 'f') {
		Hi -= ('a' - 10);
	} else if ('A' <= Hi && Hi <= 'F') {
		Hi -= ('A' - 10);
	}
	Lo = pChars[1];
	if ('0' <= Lo && Lo <= '9') {
		Lo -= '0';
	} else if ('a' <= Lo && Lo <= 'f') {
		Lo -= ('a' - 10);
	} else if ('A' <= Lo && Lo <= 'F') {
		Lo -= ('A' - 10);
	}
	Result = Lo + (16 * Hi);
	return (Result);
}



int base64decode(char *dest, char *src)
{
	char *ascii, *pBase64, *mBase64;
	char TopVal, BottomVal;
	int chars_left, i, padding, count=0;

	mBase64 = (char *) malloc(strlen(src) + 1);
	pBase64 = mBase64;
	if (pBase64 == NULL) {
		dest[0] = '\0';	// Returns null if there was a problem
		return(0);
	}

	strcpy(pBase64, src);
	ascii = dest;

	chars_left = strlen(pBase64);
	while (chars_left > 0) {
		padding = 0;
		for (i = 0; i < 4; i++) {
			if (pBase64[i] == '=') {
				padding++;
			} else if (pBase64[i] == '+') {
				pBase64[i] = 62;
			} else if (pBase64[i] == '/') {
				pBase64[i] = 63;
			} else if (pBase64[i] <= '9') {
				pBase64[i] = pBase64[i] + 52 - '0';
			} else if (pBase64[i] <= 'Z') {
				pBase64[i] = pBase64[i] - 'A';
			} else {
				pBase64[i] = pBase64[i] + 26 - 'a';
			}
		}
		TopVal = pBase64[0] << 2;
		BottomVal = pBase64[1] >> 4;
		ascii[0] = TopVal | BottomVal;
		count++;

		if (padding < 2) {
			TopVal = pBase64[1] << 4;
			BottomVal = pBase64[2] >> 2;
			ascii[1] = TopVal | BottomVal;
			count++;
			if (padding < 1) {
				TopVal = pBase64[2] << 6;
				ascii[2] = TopVal | pBase64[3];
				count++;
			} else {
				ascii[2] = '\0';
			}
		} else {
			ascii[1] = '\0';
		}

		ascii += 3;
		pBase64 += 4;
		chars_left -= 4;
	}
	*ascii = '\0';
	free(mBase64);
	return(count);
}

int base64encode(char *dest, char *src, int len)
{
        unsigned char *bin, *pBase64;
        int chars_left, count=0;
        static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bin=(unsigned char *)src;
        pBase64=(unsigned char *)dest;

        chars_left = len;
        while (chars_left > 0) {
                pBase64[0] = cb64[ bin[0] >> 2 ];
                pBase64[1] = cb64[ ((bin[0] & 0x03) << 4) | ((bin[1] & 0xf0) >> 4) ];
                chars_left--;
                pBase64[2] = (unsigned char) (chars_left > 0? cb64[ ((bin[1] & 0x0f) << 2) | ((bin[2] & 0xc0) >> 6) ] : '=');
                chars_left--;
                pBase64[3] = (unsigned char) (chars_left > 0? cb64[ bin[2] & 0x3f ] : '=');
                chars_left--;

                bin += 3;
                pBase64 += 4;
                count++;
        }
        *pBase64 = '\0';
        return(count);
}


