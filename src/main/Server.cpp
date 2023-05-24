#include "Server.h"
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>

void Server::createSocket()
{
    struct sockaddr_in addr;

    int port = configMap.getValue("port").getAsInt();
    const std::string& address = configMap.getValue("ip").getAsString();

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address.c_str());

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
        logger << "SSL Context Init Failure" << std::endl
        << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Server::configureContext()
{
    if (SSL_CTX_use_certificate_file(sslContext, "cert/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        logger << "Could not use cert file" << std::endl
        << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, "cert/key.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        logger << "Could not use key file" << std::endl <<
        ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
}

bool Server::readFile(const std::string& path, std::string& out)
{
    std::ifstream file(path);

    if (!file.is_open())
        return false;

    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize <= 0)
        return false;

    out.resize(fileSize);

    file.read(&out[0], fileSize);
    file.close();

    return true;
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

    if (request.getPathToResource() == "/")
    {
        static HttpMutableMap locationHeader;
        static bool once;

        if (!once)
        {
            locationHeader.setValue("Location", ValueWrapper("/index.html"));
            once = true;
        }

        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::FOUND)
            .setHeaderMap(&locationHeader);

        return;
    }

    if (subhandleRequestAsHardwareWrite(request))
        return;

    if (subhandleRequestAsHardwareRead(request))
        return;
    
    subhandleRequestAsFile(request);
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

    states.setValue("relay1", ValueWrapper(std::to_string((int)relayController.getLastKnownRelayStateByIndex(0))));
    states.setValue("relay2", ValueWrapper(std::to_string((int)relayController.getLastKnownRelayStateByIndex(1))));
    states.setValue("relay3", ValueWrapper(std::to_string((int)relayController.getLastKnownRelayStateByIndex(2))));
    states.setValue("relay4", ValueWrapper(std::to_string((int)relayController.getLastKnownRelayStateByIndex(3))));

    responseBuilder
        .reset()
        .setStatusCode(HttpStatusCode::OK)
        .setContentType(HttpContentType::JSON)
        .setJsonMap(&states);

    return true;
}

bool Server::subhandleRequestAsFile(const HttpRequest& request)
{
    std::string pathToResource = request.getPathToResource();

    pathToResource.insert(0, "resources");
    responseBuilder.reset();

    std::string fileContents;
    if (!readFile(pathToResource, fileContents))
    {
        responseBuilder
            .setStatusCode(HttpStatusCode::NOT_FOUND);
    }

    const std::string& extension = request.getResourceExtension();

    if (extension == "html" || extension == "HTML")
        responseBuilder.setContentType(HttpContentType::HTML);

    responseBuilder
        .setStatusCode(HttpStatusCode::OK)
        .setRawBody(fileContents);

    return true;
}

void Server::start()
{
    const int MAX_BUFFER_LENGTH = 10240;
    char buffer[MAX_BUFFER_LENGTH+1];

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
        {
            logger << "SSL accept failed" << std::endl 
            << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        }
        else 
        {
            int bytesRead;
            if ((bytesRead = SSL_read(ssl, buffer, MAX_BUFFER_LENGTH)) > 0)
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

Server::Server(std::ostream& logger)
	:	logger(logger)
{
    signal(SIGPIPE, SIG_IGN);

    createContext();
    configureContext();

    std::string rawConfig;
    readFile("config", rawConfig);

    configMap.parseKeyValuePairs(rawConfig.c_str(), '\n', '\0');

    createSocket();
}

Server::~Server()
{
	close(sock);
    SSL_CTX_free(sslContext);
}
