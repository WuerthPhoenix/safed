#ifndef MEMORYCACHE_H_
#define MEMORYCACHE_H_

#define MAX_CONFIG_LINE 512
/*
   This module provides a thread safe list implementation.
 */

typedef struct _msgcache {
	char *msg;
	int year;
	int month;
	int day;
	int seqnum;
	int error;
	struct _msgcache *next;
} Message;


Message *new_Message();
Message* getMsgFromMemoryCache();
int putMsgToMemoryCache(Message *element);
int getNumberOfMessagesInMemoryCache();


#endif /* MEMORYCACHE_H_ */
