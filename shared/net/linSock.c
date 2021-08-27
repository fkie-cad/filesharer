#include "linSock.h"



int initS()
{
	return 0;
}

void closeSocket(SOCKET* s)
{
	if ( *s == INVALID_SOCKET )
		return;

	close(*s);
	*s = INVALID_SOCKET;
}

void cleanUp(SOCKET* s)
{
	closeSocket(s);
}

int getLastSError()
{
	return errno;
}

int getLastError()
{
	return errno;
}

void checkReceiveError(int le)
{
	printf("ERROR (0x%x): Recv failed", le);
	if (le == EBADF)
		printf(": The socket argument is not a valid file descriptor.\n");
	else if (le == ECONNRESET)
		printf(": A connection was forcibly closed by a peer.\n");
	else if (le == EINTR)
		printf(": The recv() function was interrupted by a signal that was caught, before any data was available..\n");
	else if (le == ENOTCONN)
		printf(": A receive is attempted on a connection-mode socket that is not connected..\n");
	else if (le == ENOTSOCK)
		printf(": The socket argument does not refer to a socket..\n");
	else if (le == ETIMEDOUT)
		printf(": The connection timed out during connection establishment, or due to a transmission timeout on active connection..\n");
	else if (le == EIO)
		printf(": An I/O error occurred while reading from or writing to the file system..\n");
	else if (le == ENOBUFS)
		printf(": Insufficient resources were available in the system to perform the operation..\n");
	else if (le == ENOMEM)
		printf(": Insufficient memory was available to fulfill the request..\n");
	else
		printf(".\n");
}
