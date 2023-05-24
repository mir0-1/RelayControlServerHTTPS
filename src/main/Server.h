#include <iostream>
#include <openssl/ssl.h>
#include <vector>
#include "../../../HttpLibrary/src/HttpRequest.h"
#include "../../../HttpLibrary/src/HttpResponseBuilder.h"
#include "../../../VoltageLibrary/VoltageReader.h"
#include "../../../RelayLibrary/RelayController.h"

class Server
{
	private:
		std::vector<std::string> sessions;
		CommonParsableMap configMap;
		std::ostream& logger;
		int sock;
		SSL_CTX* sslContext;
		HttpResponseBuilder responseBuilder;
		VoltageReader voltageReader;
		RelayController relayController;

		bool readFile(std::string& out);
		void createSocket(const char* address, int port);
		void createContext();
		void configureContext();
		void handleRequest(const HttpRequest& request);
		bool subhandleRequestAsHardwareRead(const HttpRequest& request);
		bool subhandleRequestAsHardwareWrite(const HttpRequest& request);
		bool subhandleRequestAsFile(const HttpRequest& request);

	public:
		void start();

		Server(const char* ipAddress, int port, std::ostream& logger);
		~Server();
};
