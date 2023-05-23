#include <iostream>
#include <openssl/ssl.h>
#include "../../../HttpLibrary/src/HttpRequest.h"
#include "../../../HttpLibrary/src/HttpResponseBuilder.h"

class Server
{
	private:
		std::ostream& logger;
		int sock;
		SSL_CTX* sslContext;
		HttpResponseBuilder responseBuilder;

		void createSocket(const char* address, int port);
		void createContext();
		void configureContext();
		void handleRequest(const HttpRequest& request);

	public:
		void start();

		Server(const char* ipAddress, int port, std::ostream& logger);
		~Server();
};
