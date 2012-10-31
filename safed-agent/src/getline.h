#ifndef GETLINE_H_
#define GETLINE_H_

ssize_t getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp);

ssize_t getline(char **lineptr, size_t *n, FILE *fp);

#endif /* GETLINE_H_ */
