// Chat.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WinSock2.h>
#include <iostream>
#include <thread>
#include "..\bfsh-koc\blowfish.h"
#include "..\md5\md5.h"

SOCKET sendSocket;
SOCKET receiveSocket;
sockaddr_in remoteSendSocketAddress;
sockaddr_in remoteReceiveSocketAddress;
BLOWFISH_CTX blowfishContext;
char * acknowledgePendingBuffer = NULL;

// Función para imprimir un buffer
void PrintBuffer(char * buffer, int bufferLenght)
{
	for (int i = 0; i < bufferLenght; i++)
	{
		if (i < bufferLenght - 1)
		{
			fprintf(stdout, "%02x ", ((unsigned char *) buffer) [i] & 0xff);
		}
		else
		{
			fprintf(stdout, "%02x\n", ((unsigned char *) buffer) [i] & 0xff);
		}
	}
}

// Función Send para el hilo de envío
void Send ()
{
	// Declarar variables locales de la función Send
	int size = 0;
	int padSize = 0;
	char * buffer = NULL;
	char * extendedBuffer = NULL;
	int remoteSendSocketAddressSize = sizeof(remoteSendSocketAddress);
	md5_context md5Context;
	unsigned char md5Digest [16] = "";

	// Bucle infinito del hilo
	while (true)
	{
		// Obtener el siguiente carácter de la entrada estándar
		char character = std::cin.get();

		// El carácter es fin de línea
		if (character == '\n')
		{
			// El tamaño del mensaje es mayor que cero
			if (size > 0)
			{
				// Extender el buffer de envío
				size++;
				extendedBuffer = (char *) realloc(buffer, size);
				
				// Llenar el buffer de envío
				if (extendedBuffer != NULL)
				{
					buffer = extendedBuffer;
					buffer[size - 1] = character;
				}

				// No existe mensaje por confirmar
				if (! acknowledgePendingBuffer)
				{
					// Calcular el tamaño de pad
					padSize = (size % 8 > 0 ? 8 - (size % 8) : 0);
					// Reservar buffer para mensaje cifrado. Tamaño se extiende hasta multiplo de 64 bits / 8 bytes
					char * cipheredBuffer = (char *) malloc(sizeof(char) * (size + padSize) + sizeof(int));
					// Rellenar inicio del buffer con el tamaño del mensaje
					* ((int *) cipheredBuffer) = size + padSize;
					// Inicializar a 0 el buffer
					memset(cipheredBuffer + sizeof(int), 0, size + padSize);
					// Copiar mensaje al buffer
					memcpy(cipheredBuffer + sizeof(int), buffer, size);

					// Calcular el md5 hash del mensaje
					md5_starts(& md5Context);
					md5_update(& md5Context, (uint8 *) (cipheredBuffer + sizeof(int)), size + padSize);
					md5_finish(& md5Context, (unsigned char *) md5Digest);

					// Establecer que existe mensaje por confirmar. Guardando su hash en buffer reservado
					acknowledgePendingBuffer = (char *) malloc(sizeof(char) * 16);
					memcpy(acknowledgePendingBuffer, md5Digest, sizeof(char) * 16);

					// Cifrar el mensaje
					for (int i = 0; i < size + padSize; i += 2 * sizeof(unsigned long))
					{
						Blowfish_Encrypt(& blowfishContext, (unsigned long *) (cipheredBuffer + sizeof(int) + i), (unsigned long *) (cipheredBuffer + sizeof(int) + i + sizeof(unsigned long)));
					}

					// Proporcionar información por la salida estándar
					fprintf(stdout, "Lenght received: %d\n", size);
					fprintf(stdout, "Lenght padded: %d\n", size + padSize);
					fprintf(stdout, "Received: ");
					PrintBuffer(buffer, size);
					fprintf(stdout, "Hash: ");
					PrintBuffer((char *) md5Digest, 16);
					fprintf(stdout, "Ciphered: ");
					PrintBuffer(cipheredBuffer + sizeof(int), size + padSize);

					// Declarar variables para bytes enviados y offset de envío en buffer
					int bytesSent = 0;
					int offset = 0;

					// Actualizr el tamaño del mensaje incrementandolo con la longitud de cabeza y el pad
					size += sizeof(int) + padSize;

					// Transmitir el buffer por el socket de envío
					do
					{
						bytesSent = sendto(sendSocket, cipheredBuffer + offset, size, 0, (SOCKADDR *) & remoteSendSocketAddress, remoteSendSocketAddressSize);
						offset += bytesSent;
						size -= bytesSent;
					} while(size > 0);

					// Liberar buffers reservados
					free(buffer);
					free(cipheredBuffer);
					buffer = NULL;
					extendedBuffer = NULL;
					cipheredBuffer = NULL;
				}
			}
		}
		else
		{
			// Extender el buffer de envío
			size++;
			extendedBuffer = (char *) realloc(buffer, size);
			
			// Llenar el buffer de envío
			if (extendedBuffer != NULL)
			{
				buffer = extendedBuffer;
				buffer[size - 1] = character;
			}
		}
	}
}

// Función Receive para el hilo de recepción
void Receive ()
{
	// Declarar variables locales de la función Receive
	int size = 0;
	char * buffer = NULL;
	char * extendedBuffer = NULL;
	int remoteSendSocketAddressSize = sizeof(remoteSendSocketAddress);
	int remoteReceiveSocketAddressSize = sizeof(remoteReceiveSocketAddress);
	char receivedBuffer[65536];
	int lastBytes = 0;
	int cipheredBufferLenght = 0;
	md5_context md5Context;
	unsigned char md5Digest [16] = "";

	// Bucle infinito del hilo
	while (true)
	{
		// Inicializar buffer de recepción del socket a 0
		memset(receivedBuffer, 0, 65536);

		// Recibir mensaje del socket de recepción
		int bytesReceived = recvfrom(receiveSocket, receivedBuffer, 65536, 0, (SOCKADDR *) & remoteReceiveSocketAddress, & remoteReceiveSocketAddressSize);

		// Actualizar la longitud del mensaje recibido
		if (! cipheredBufferLenght)
		{
			cipheredBufferLenght = * ((int *) receivedBuffer) + sizeof(int);
		}

		// Aún no se ha recibido la cantidad necesaria
		if (size + bytesReceived < cipheredBufferLenght)
		{
			// Extender el buffer de recepción del mensaje
			size += bytesReceived;
			extendedBuffer = (char *) realloc(buffer, size);
			
			// Llenar el buffer de recepción del mensaje
			if (extendedBuffer != NULL)
			{
				buffer = extendedBuffer;
				memcpy(buffer + size - bytesReceived, receivedBuffer, bytesReceived);
			}
		}
		else
		{
			// Calcular cantidad de bytes tras el delimitador
			lastBytes = size + bytesReceived - cipheredBufferLenght;
			// Extender buffer de recepción del mensaje hasta el delimitador
			extendedBuffer = (char *) realloc(buffer, size + bytesReceived - lastBytes);
			
			// Llenar buffer de recepción del mensaje hasta el delimitador
			if (extendedBuffer != NULL)
			{
				buffer = extendedBuffer;
				memcpy(buffer + size, receivedBuffer, bytesReceived - lastBytes);
			}

			// Reservar buffer para el mensaje descifrado
			char * decipheredBuffer = (char *) malloc((cipheredBufferLenght) * sizeof(char) - sizeof(int) + 1);
			// Rellenar buffer para el mensaje descrifrado con el mensaje cifrado
			memcpy(decipheredBuffer, buffer + sizeof(int), cipheredBufferLenght - sizeof(int));
			// Delimitar buffer para el mensaje descifrado
			decipheredBuffer[cipheredBufferLenght - sizeof(int) + 1] = '\0';

			// Descifrar el mensaje
			for (int i = 0; i < cipheredBufferLenght; i += 2 * sizeof(unsigned long))
			{
				Blowfish_Decrypt(& blowfishContext, (unsigned long *) (decipheredBuffer + i), (unsigned long *) (decipheredBuffer + i + sizeof(unsigned long)));
			}

			// No existe mensaje por confirmar
			if (! acknowledgePendingBuffer)
			{
				// Calcular el md5 hash del mensaje
				md5_starts(& md5Context);
				md5_update(& md5Context, (uint8 *) decipheredBuffer, cipheredBufferLenght - sizeof(int));
				md5_finish(& md5Context, (unsigned char *) md5Digest);

				// Proporcionar información por la salida estándar
				fprintf(stdout, "Lenght ciphered: %d\n", *((int *) buffer));
				fprintf(stdout, "Ciphered: ");
				PrintBuffer(buffer + sizeof(int), cipheredBufferLenght - sizeof(int));
				fprintf(stdout, "Deciphered: %s\n", decipheredBuffer);
				fprintf(stdout, "Hash: ");
				PrintBuffer((char *) md5Digest, 16);

				// Reservar buffer para el mensaje cifrado
				char * cipheredBuffer = (char *) malloc(sizeof(char) * 16 + sizeof(int));
				// Rellenar inicio del buffer con el tamaño del mensaje
				* ((int *) cipheredBuffer) = 16;
				// Inicializar a 0 el buffer
				memset(cipheredBuffer + sizeof(int), 0, 16);
				// Copiar mensaje al buffer
				memcpy(cipheredBuffer + sizeof(int), md5Digest, 16);

				// Cifrar mensaje
				for (int i = 0; i < 16; i += 2 * sizeof(unsigned long))
				{
					Blowfish_Encrypt(& blowfishContext, (unsigned long *) (cipheredBuffer + sizeof(int) + i), (unsigned long *) (cipheredBuffer + sizeof(int) + i + sizeof(unsigned long)));
				}


				// Declarar variables para bytes enviados y offset de envío en buffer
				int bytesSent = 0;
				int offset = 0;

				// Inicializar el tamaño enviado del mensaje incrementandolo con la longitud de cabeza
				int sentSize = sizeof(int) + 16;

				do
				{
					// Transmitir el buffer por el socket de envío
					bytesSent = sendto(sendSocket, cipheredBuffer + offset, sentSize, 0, (SOCKADDR *) & remoteSendSocketAddress, remoteSendSocketAddressSize);
					offset += bytesSent;
					sentSize -= bytesSent;
				} while(sentSize > 0);

				// Extender buffer de recepción del mensaje a la cantidad de bytes tras el delimitador
				extendedBuffer = (char *) realloc(buffer, lastBytes);
				
				// Llenar buffer de recepción del mensaje con bytes tras delimitador
				if (extendedBuffer != NULL)
				{
					buffer = extendedBuffer;
					memcpy(buffer, receivedBuffer + bytesReceived - lastBytes, lastBytes);
					cipheredBufferLenght = *((int *) buffer) + sizeof(int);
				}
				else
				{
					buffer = NULL;
					extendedBuffer = NULL;
					cipheredBufferLenght = 0;
					size = 0;
				}
			}
			else
			{
				// Comprobar que el mensaje recibido es el la confirmación de uno anterior
				if (!memcmp(acknowledgePendingBuffer, decipheredBuffer, cipheredBufferLenght - sizeof(int)))
				{
					// Liberar el buffer del hash del mensaje por confirmar
					free(acknowledgePendingBuffer);
					acknowledgePendingBuffer = NULL;

					// Proporcionar información por la salida estándar
					fprintf(stdout, "Acknowledged!\n");

					// Extender buffer de recepción del mensaje a la cantidad de bytes tras el delimitador
					extendedBuffer = (char *) realloc(buffer, lastBytes);

					// Llenar buffer de recepción del mensaje con bytes tras delimitador
					if (extendedBuffer != NULL)
					{
						buffer = extendedBuffer;
						memcpy(buffer, receivedBuffer + bytesReceived - lastBytes, lastBytes);
						cipheredBufferLenght = *((int *) buffer) + sizeof(int);
					}
					else
					{
						buffer = NULL;
						extendedBuffer = NULL;
						cipheredBufferLenght = 0;
						size = 0;
					}
				}
				else
				{
					// Proporcionar información por la salida estándar
					fprintf(stdout, "Not acknowledged!\n");

					// Extender buffer de recepción del mensaje a la cantidad de bytes recibidos
					extendedBuffer = (char *) realloc(buffer, size + bytesReceived);
				
					// Llenar buffer de recepción del mensaje con los bytes recibidos
					if (extendedBuffer != NULL)
					{
						buffer = extendedBuffer;
						memcpy(buffer + size + bytesReceived - lastBytes, receivedBuffer + bytesReceived - lastBytes, lastBytes);
					}
					else
					{
						buffer = NULL;
						extendedBuffer = NULL;
						cipheredBufferLenght = 0;
						size = 0;
					}
				}
			}
		}
	}

	// Liberar buffer de recepción del mensaje
	if (buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
		extendedBuffer = NULL;
	}

	// Liberar buffer de la confirmación de mensaje 
	if (acknowledgePendingBuffer != NULL)
	{
		free(acknowledgePendingBuffer);
		acknowledgePendingBuffer = NULL;
	}
}

// Función principal
int main(int argc, char * argv[])
{
	// Declarar variables locales de la función main
	int result = 0;
	WSAData wsaData;
	int addressFamily = PF_INET;
	int socketType = SOCK_DGRAM;
	int protocolType = IPPROTO_UDP;
	sockaddr_in localSendSocketAddress;
	sockaddr_in localReceiveSocketAddress;
	char * localIpAddress = NULL;
	u_short localPort = 31373;
	char * remoteIpAddress = "127.0.0.1";
	u_short remotePort = 31373;
	char * key = NULL;

	if (argc == 6)
	{
		// Recibir parámetros
		localIpAddress = argv[1];
		localPort = strtoul(argv[2], NULL, 10);
		remoteIpAddress = argv[3];
		remotePort = strtoul(argv[4], NULL, 10);
		key = argv[5];

		// Inicializar contexto blowfish y windows sockets
		Blowfish_Init (& blowfishContext, (unsigned char*) key, sizeof(key));
		result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		
		// Inicializar puntos de acceso
		memset(& localSendSocketAddress, 0, sizeof(sockaddr_in));
		memset(& localReceiveSocketAddress, 0, sizeof(sockaddr_in));
		memset(& remoteSendSocketAddress, 0, sizeof(sockaddr_in));
		memset(& remoteReceiveSocketAddress, 0, sizeof(sockaddr_in));

		if (result == NO_ERROR)
		{
			// Crear socket de envío
			sendSocket = socket(addressFamily, socketType, protocolType);
			
			if (sendSocket != INVALID_SOCKET)
			{
				// Crear punto de acceso local de envío
				localSendSocketAddress.sin_family = AF_INET;
				localSendSocketAddress.sin_addr.S_un.S_addr = INADDR_ANY;
				localSendSocketAddress.sin_port = 0;

				// Enlazar socket de envío a punto de acceso local de envío
				result = bind(sendSocket, (SOCKADDR *) & localSendSocketAddress, sizeof(localSendSocketAddress));

				if (result != SOCKET_ERROR)
				{
					// Crear socket de recepción
					receiveSocket = socket(addressFamily, socketType, protocolType);

					if (sendSocket != INVALID_SOCKET)
					{
						// Crear punto de acceso local de recepción
						localReceiveSocketAddress.sin_family = AF_INET;
						localReceiveSocketAddress.sin_addr.S_un.S_addr = inet_addr(localIpAddress);
						localReceiveSocketAddress.sin_port = htons(localPort);

						// Enlazar socket de recepción a punto de acceso local de recepción
						result = bind(receiveSocket, (SOCKADDR *) & localReceiveSocketAddress, sizeof(localReceiveSocketAddress));

						if (result != SOCKET_ERROR)
						{
							// Crear punto de acceso remoto de envío
							remoteSendSocketAddress.sin_family = AF_INET;
							remoteSendSocketAddress.sin_addr.S_un.S_addr = inet_addr(remoteIpAddress);
							remoteSendSocketAddress.sin_port = htons(remotePort);
							
							// Crear hilo de envío con función Send
							std::thread sendThread = std::thread(Send);
							// Crear hilo de recepción con función Receive
							std::thread receiveThread = std::thread(Receive);
							// Esperar hilo de envío
							sendThread.join();
							// Esperar hilo de recepción
							receiveThread.join();
						}
						else
						{
							fprintf(stderr, "Error: bind error: %u", WSAGetLastError());
						}
					}
					else
					{
						fprintf(stderr, "Error: socket error: %u", WSAGetLastError());
					}
				}
				else
				{
					fprintf(stderr, "Error: bind error: %u", WSAGetLastError());
				}
			}
			else
			{
				fprintf(stderr, "Error: socket error: %u", WSAGetLastError());
			}

			WSACleanup();
		}
		else
		{
			fprintf(stderr, "Error: WSAStartup error %u", WSAGetLastError());
		}
	}
	else
	{
		fprintf(stderr, "Usage: Chat localIP localPort remoteIP remotePort password");
	}

	return result;
}
