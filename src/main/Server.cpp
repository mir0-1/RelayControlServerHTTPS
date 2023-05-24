#include "Server.h"
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <fstream>


void Server::createSocket(const char* address, int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        logger << "Socket creation failure" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
    {
        logger << "Unable to bind" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) 
    {
        logger << "Unable to listen" << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Server::createContext()
{
    const SSL_METHOD *method;

    method = TLS_server_method();

    sslContext = SSL_CTX_new(method);
    if (!sslContext) 
    {
        logger << "SSL Context Init Failure" << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Server::configureContext()
{
    if (SSL_CTX_use_certificate_file(sslContext, "cert/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        logger << "Could not use cert file" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, "cert/key.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        logger << "Could not use key file" << std::endl;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
}

void Server::handleRequest(const HttpRequest& request)
{
    HttpRequestType requestType = request.getRequestType();
    if (!request.isValid() || (requestType != HttpRequestType::GET && requestType != HttpRequestType::PUT))
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::NOT_FOUND);

        return;
    }

    if (!subhandleRequestAsHardwareWrite(request))
        if(!subhandleRequestAsHardwareRead(request))
            if(!subhandleRequestAsFile(request))
                responseBuilder
                    .reset()
                    .setStatusCode(HttpStatusCode::BAD_REQUEST);
}

bool Server::subhandleRequestAsHardwareWrite(const HttpRequest& request)
{
    if (request.getRequestType() != HttpRequestType::PUT)
        return false;

    if (request.getPathToResource() != "/relay")
        return false;

    const HttpImmutableMap& bodyParams = request.getBodyParametersMap();

    if (!bodyParams.hasKey("index") ||
        !bodyParams.hasKey("on"))
    {
            responseBuilder
                .reset()
                .setStatusCode(HttpStatusCode::BAD_REQUEST);

            return true;
    }

    const ValueWrapper& index = bodyParams.getValue("index");
    const ValueWrapper& on = bodyParams.getValue("on");

    if (!index.isInt() || !on.isInt())
    {
        responseBuilder
                .reset()
                .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return true;
    }

    int indexInt = index.getAsInt();
    int onInt = on.getAsInt();

    if (onInt != 0)
        relayController.enableRelayByIndex(indexInt);
    else
        relayController.disableRelayByIndex(indexInt);

    responseBuilder
        .reset()
        .setStatusCode(HttpStatusCode::OK);

    return true;
}

bool Server::subhandleRequestAsHardwareRead(const HttpRequest& request)
{
    if (request.getRequestType() != HttpRequestType::GET)
        return false;

    const std::string& pathToResource = request.getPathToResource();

    if (pathToResource != "/state")
        return false;

    static HttpMutableMap states;

    states.setValue("voltage1", ValueWrapper(std::to_string(voltageReader.getVoltage(0))));
    states.setValue("voltage2", ValueWrapper(std::to_string(voltageReader.getVoltage(1))));
    states.setValue("voltage3", ValueWrapper(std::to_string(voltageReader.getVoltage(2))));
    states.setValue("voltage4", ValueWrapper(std::to_string(voltageReader.getVoltage(3))));

    states.setValue("relay1", ValueWrapper(std::to_string(relayController.getLastKnownRelayStateByIndex(0))));
    states.setValue("relay2", ValueWrapper(std::to_string(relayController.getLastKnownRelayStateByIndex(1))));
    states.setValue("relay3", ValueWrapper(std::to_string(relayController.getLastKnownRelayStateByIndex(2))));
    states.setValue("relay4", ValueWrapper(std::to_string(relayController.getLastKnownRelayStateByIndex(3))));

    responseBuilder
        .reset()
        .setStatusCode(HttpStatusCode::OK)
        .setJsonMap(&states);

    return true;
}

bool Server::subhandleRequestAsFile(const HttpRequest& request)
{
    std::string pathToResource = request.getPathToResource();

    pathToResource.insert(0, "resources");

    std::ifstream file(pathToResource);

    if (file.is_open())
    {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        std::string fileContents;
        fileContents.resize(fileSize);

        file.read(&fileContents[0], fileSize);
        file.close();

        const std::string& extension = request.getResourceExtension();

        responseBuilder.reset();

        if (extension == "html" || extension == "HTML")
            responseBuilder.setContentType(HttpContentType::HTML);

        responseBuilder
            .setStatusCode(HttpStatusCode::OK)
            .setRawBody(fileContents);

        return true;
    } 

    return false;
}

void Server::start()
{
    char buffer[4096];

    while(true)
    {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) 
        {
            logger << "Unable to accept" << std::endl;
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(sslContext);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) 
            logger << "SSL accept failed" << std::endl;
        else 
        {
            int bytesRead;
            if ((bytesRead = SSL_read(ssl, buffer, 4096)) > 0)
            {
                buffer[bytesRead] = '\0';
                HttpRequest request(buffer);

                handleRequest(request);
                std::string reply = responseBuilder.build();

                SSL_write(ssl, reply.c_str(), reply.length());
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }
}

Server::Server(const char* ipAddress, int port, std::ostream& logger)
	:	logger(logger)
{
    signal(SIGPIPE, SIG_IGN);

    createContext();
    configureContext();

    createSocket(ipAddress, port);
    responseBuilder.setProtocolVersion(1.1);
}

Server::~Server()
{
	close(sock);
    SSL_CTX_free(sslContext);
}
