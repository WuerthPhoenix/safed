/*
 * webutilities.h
 *
 *
 */

#ifndef WEBUTILITIES_H_
#define WEBUTILITIES_H_

int	hex2int(char *pChars);
int	base64decode(char *dest, char *src);
int base64encode(char *dest, char *src, int len);


#endif /* WEBUTILITIES_H_ */
