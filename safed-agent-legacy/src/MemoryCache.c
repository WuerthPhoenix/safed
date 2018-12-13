#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "MemoryCache.h"



pthread_mutex_t msgMutex = PTHREAD_MUTEX_INITIALIZER;

int numMessagesInCache = 0;
Message *messageHead=NULL;
Message *messageTail=NULL;

/**
 * Allocates a new Message object, and returns its pointer.
 */
Message *new_Message() {
	Message *result = (Message *)malloc(sizeof(Message));
	memset(result, 0, sizeof(Message));
	return result;
}

/**
 * Returns the first Message object in the queue; if the queue is empty it returns NULL.
 */
Message* getMsgFromMemoryCache() {
	Message* result = NULL;
	pthread_mutex_lock(&msgMutex);
	if (messageHead) {
		// removing the element from the queue
		result = messageHead;
		messageHead = messageHead->next;
		result->next = NULL;
		numMessagesInCache--;
	}
	if (!messageHead) {
		messageTail = NULL;
	}
	pthread_mutex_unlock(&msgMutex);

	return result;
}

/**
 * Puts the message in the queue. It allocates the required space trough malloc().
 */
int putMsgToMemoryCache(Message *element) {
	pthread_mutex_lock(&msgMutex);

	// the newly added message is the last one (the tail)
	if (messageTail) {
		messageTail->next=element;
	}

	messageTail = element;

	if (!messageHead) {
		// if the list is empty, the new message is also the head of the list
		messageHead = element;
	}

	// incrementing the number of messages in the memory message cache
	numMessagesInCache++;
	pthread_mutex_unlock(&msgMutex);

	return 0;
}

/**
 * Returns the number of messages in the queue.
 */
int getNumberOfMessagesInMemoryCache() {
	return numMessagesInCache;
}
