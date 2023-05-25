#include <iostream>
#include <openssl/ssl.h>
#include <vector>
#include "../../../HttpLibrary/src/HttpRequest.h"
#include "../../../HttpLibrary/src/HttpResponseBuilder.h"
#include "../../../VoltageLibrary/VoltageReader.h"
#include "../../../RelayLibrary/RelayController.h"
#include "../../../WirelessLibrary/WirelessConnectionManager.h"

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
		WirelessConnectionManager* wirelessConnectionManager;

		std::string generateRandomSessionID();
		const std::string& getSessionID(const HttpRequest& request);
		bool readFile(const std::string& path, std::string& out);
		bool writeFile(const std::string& path, const std::string& contents);
		void createSocket();
		void createContext();
		void configureContext();
		void handleRequest(const HttpRequest& request);
		bool subhandleRequestAsLogin(const HttpRequest& request);
		bool subhandleRequestAsHardwareRead(const HttpRequest& request);
		bool subhandleRequestAsHardwareWrite(const HttpRequest& request);
		bool subhandleRequestAsConfig(const HttpRequest& request);
		bool subhandleRequestAsFile(const HttpRequest& request);

	public:
		void start();

		Server(std::ostream& logger);
		~Server();
};
