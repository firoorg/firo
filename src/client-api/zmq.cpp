#include "client-api/zmq.h"
#include "client-api/server.h"
#include "zmq/zmqpublishnotifier.h"
#include "util.h"
#include <zmq.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>


void *zmqpcontext;
void *zmqpsocket;

void zmqError(const char *str)
{
    LogPrint(NULL, "zmq: Error: %s, errno=%s\n", str, zmq_strerror(errno));
}

pthread_mutex_t mxq;
int needStopREQREPZMQ(){
	switch(pthread_mutex_trylock(&mxq)) {
	case 0: /* if we got the lock, unlock and return 1 (true) */
		pthread_mutex_unlock(&mxq);
		return 1;
	case EBUSY: /* return 0 (false) if the mutex was locked */
		return 0;
	}
	return 1;
}

// arg[0] is the broker
static void* REQREP_ZMQ(void *arg)
{
	while (1) {
		// 1. get request message
		// 2. do something in tableZMQ
		// 3. reply result

	    /* Create an empty ØMQ message to hold the message part */
	    zmq_msg_t part;
	    int rc = zmq_msg_init (&part);
	    assert (rc == 0);
	    /* Block until a message is available to be received from socket */
	    rc = zmq_recvmsg (zmqpsocket, &part, 0);
	    LogPrint(NULL, "ZMQ: Received message part\n");
	    LogPrint(NULL, "ZMQ: Part: ");
		LogPrint(NULL, (char*) zmq_msg_data (&part));
		LogPrint(NULL, "\n");
	    assert (rc != -1);


        /* send reply (example) */
    	zmq_msg_t reply;
        rc = zmq_msg_init_size (&reply, 5);
        assert(rc == 0);
        string reply_str = "World";
        std::memcpy (zmq_msg_data (&reply), reply_str.data(), reply_str.size());
        LogPrint(NULL, "ZMQ: Sending reply..\n");
        /* Block until a message is available to be sent from socket */
        rc = zmq_sendmsg (zmqpsocket, &reply, 0);
        assert(rc!=-1);

        LogPrint(NULL, "ZMQ: Reply sent.\n");
        zmq_msg_close 	(&reply);

	}

	return (void*)true;
}

bool StartREQREPZMQ()
{
	LogPrint(NULL, "ZMQ: Starting REQ/REP ZMQ server\n");
	// TODO authentication

	zmqpcontext = zmq_ctx_new();

	zmqpsocket = zmq_socket(zmqpcontext,ZMQ_REP);
	if(!zmqpsocket){
		LogPrint(NULL, "ZMQ: Failed to create socket\n");
		//zmqError("Failed to create socket");
		return false;
	}

	int rc = zmq_bind(zmqpsocket, "tcp://*:5556");
	LogPrint(NULL, "ZMQ: Bound socket\n");
	if (rc == -1)
	{
		LogPrint(NULL, "ZMQ: Unable to send ZMQ msg");
		return false;
	}

	//pthread_mutex_init(&mxq,NULL);
	//pthread_mutex_lock(&mxq);
    //create worker & run a thread 
	pthread_t worker;
	pthread_create(&worker,NULL, REQREP_ZMQ, NULL);
	return true;
}

void InterruptREQREPZMQ()
{
	LogPrint("zmq", "Interrupt REQ/REP ZMQ server\n");
}

void StopREQREPZMQ()
{
	LogPrint("zmq", "Stopping REQ/REP ZMQ server\n");
	pthread_mutex_unlock(&mxq);
}
