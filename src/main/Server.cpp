#include "Server.h"
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <algorithm>

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

bool Server::writeFile(const std::string& path, const std::string& contents)
{
    std::ofstream file(path);

    if (!file.is_open())
        return false;

    file.write(contents.c_str(), contents.length());
    file.close();

    return true;
}

void Server::handleRequest(const HttpRequest& request)
{
    HttpRequestType requestType = request.getRequestType();
    if (!request.isValid())
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return;
    }

    if (subhandleRequestAsHardwareWrite(request))
        return;

    if (subhandleRequestAsHardwareRead(request))
        return;

    if (subhandleRequestAsLogin(request))
        return;

    if (subhandleRequestAsConfig(request))
        return;
    
    subhandleRequestAsFile(request);
}

bool Server::subhandleRequestAsHardwareWrite(const HttpRequest& request)
{
    if (request.getPathToResource() != "/relay")
        return false;

    const HttpImmutableMap& bodyParams = request.getBodyParametersMap();

    if (request.getRequestType() != HttpRequestType::PUT ||
        !bodyParams.hasKey("index") ||
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

    if (getSessionID(request).empty())
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::UNAUTHORIZED);

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
    const std::string& pathToResource = request.getPathToResource();

    if (pathToResource != "/state")
        return false;

    if (request.getRequestType() != HttpRequestType::GET)
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return true;
    }

    if (getSessionID(request).empty())
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::UNAUTHORIZED);

        return true;
    }

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
    if (request.getRequestType() != HttpRequestType::GET)
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return true;
    }

    const std::string& sessionID = getSessionID(request);
    static HttpMutableMap locationHeader;

    std::string pathToResource = request.getPathToResource();
    if (pathToResource == "/")
    {
        if (!sessionID.empty())
            locationHeader.setValue("Location", ValueWrapper("/index.html"));
        else
            locationHeader.setValue("Location", ValueWrapper("/login.html"));

        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::FOUND)
            .setHeaderMap(&locationHeader);

        return true;
    }

    pathToResource.insert(0, "resources");
    std::string fileContents;

    if (!readFile(pathToResource, fileContents))
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::NOT_FOUND);

        return true;
    }

    const std::string& extension = request.getResourceExtension();
    responseBuilder.reset();

    if (extension == "html" || extension == "HTML")
        responseBuilder.setContentType(HttpContentType::HTML);

    responseBuilder
        .setStatusCode(HttpStatusCode::OK)
        .setRawBody(fileContents);

    return true;
}

std::string Server::generateRandomSessionID() 
{
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    const int length = 16;
    std::string randomString;
    for (int i = 0; i < length; ++i) {
        int randomIndex = rand() % characters.length();
        randomString += characters[randomIndex];
    }

    return randomString;
}

bool Server::subhandleRequestAsLogin(const HttpRequest& request)
{
    std::string pathToResource = request.getPathToResource();
    if (pathToResource != "/login")
        return false;

    const HttpImmutableMap& bodyParams = request.getBodyParametersMap();

    if (request.getRequestType() != HttpRequestType::POST || !bodyParams.hasKey("username") || !bodyParams.hasKey("password"))
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return true;
    }

    const std::string& username = bodyParams.getValue("username").getAsString();
    const std::string& password = bodyParams.getValue("password").getAsString();

    if (username != configMap.getValue("login_user").getAsString() ||
        password != configMap.getValue("login_password").getAsString() )
    {
        responseBuilder
            .reset()
            .setRawBody("Invalid login credentials")
            .setStatusCode(HttpStatusCode::UNAUTHORIZED);

        return true;
    }

    std::string newSessionId;
    const HttpImmutableMap& cookies = request.getCookiesMap();
    const std::string& sessionId = getSessionID(request);

    static HttpMutableMap locationHeader;
    static bool once;
    if (sessionId.empty())
    {
        do
        {
            newSessionId = generateRandomSessionID();
        } while (std::find(sessions.begin(), sessions.end(), sessionId) != sessions.end());

        sessions.push_back(newSessionId);

        if (!once)
        {
            locationHeader.setValue("Location", ValueWrapper("/index.html"));
            once = true;
        }
    }

    static HttpMutableMap cookieMap;

    cookieMap.setValue("SESSIONID", ValueWrapper(newSessionId));

    responseBuilder
        .reset()
        .setStatusCode(HttpStatusCode::FOUND)
        .setHeaderMap(&locationHeader)
        .setCookieMap(&cookieMap);

    return true;
}

bool Server::subhandleRequestAsConfig(const HttpRequest& request)
{
    if (request.getPathToResource() != "/config")
        return false;

    HttpRequestType requestType = request.getRequestType();

    if (requestType != HttpRequestType::GET && requestType != HttpRequestType::PUT)
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::BAD_REQUEST);

        return true;
    }

    if (getSessionID(request).empty())
    {
        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::UNAUTHORIZED);

        return true;
    }

    if (requestType == HttpRequestType::PUT)
    {
        const HttpImmutableMap& bodyParams = request.getBodyParametersMap();

        const std::string& ssid = bodyParams.getValue("ssid").getAsString();
        const std::string& password = bodyParams.getValue("password").getAsString();
        const std::string& login_user = bodyParams.getValue("login_user").getAsString();
        const std::string& login_password = bodyParams.getValue("login_password").getAsString();

        logger << ssid << std::endl;
        logger << password << std::endl;
        logger << login_user << std::endl;
        logger << login_password << std::endl;

        if (!ssid.empty())
            configMap.setValue("ssid", ValueWrapper(ssid));

        if (!password.empty())
            configMap.setValue("password", ValueWrapper(password));

       if (!login_user.empty())
            configMap.setValue("login_user", ValueWrapper(login_user));

       if (!login_password.empty())
            configMap.setValue("login_password", ValueWrapper(login_password));

        if (!writeFile("config", configMap.toString()))
        {
            responseBuilder
                .reset()
                .setRawBody("Internal server error")
                .setStatusCode(HttpStatusCode::INTERNAL_SERVER_ERROR);

            return true;
        }

        responseBuilder
            .reset()
            .setStatusCode(HttpStatusCode::OK);

        return true;
    }

    responseBuilder
        .reset()
        .setJsonMap(&configMap)
        .setStatusCode(HttpStatusCode::OK);

    return true;
}

const std::string& Server::getSessionID(const HttpRequest& request)
{
    static std::string emptySessionID;

    const HttpImmutableMap& cookies = request.getCookiesMap();

    if (!cookies.hasKey("SESSIONID"))
        return emptySessionID;

    const std::string& sessionID = cookies.getValue("SESSIONID").getAsString();

    if (sessionID.empty() || std::find(sessions.begin(), sessions.end(), sessionID) == sessions.end())
        return emptySessionID;

    return sessionID;

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

        if (SSL_accept(ssl) > 0) 
        {
            logger << "SSL accept success" << std::endl;
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
    srand(time(NULL));
    createContext();
    configureContext();

    std::string rawConfig;
    if (!readFile("config", rawConfig))
    {
        logger << "No config present" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (configMap.parseKeyValuePairs((char*)rawConfig.data(), '\n', '\0') == nullptr)
    {
        logger << "Invalid config format" << std::endl;
        exit(EXIT_FAILURE);
    }

    const std::string& ssid = configMap.getValue("ssid").getAsString();
    const std::string& password = configMap.getValue("password").getAsString();
    const std::string& loginUser = configMap.getValue("login_user").getAsString();
    const std::string& loginPassword = configMap.getValue("login_password").getAsString();

    if (ssid.empty() ||
        password.empty() ||
        loginUser.empty() ||
        loginPassword.empty())
    {
        logger << "Illegal empty values detected (or missing values) from config" << std::endl;
        exit(EXIT_FAILURE);
    }

    wirelessConnectionManager = new WirelessConnectionManager(ssid, password);

    createSocket();
    start();
}

Server::~Server()
{
	close(sock);
    SSL_CTX_free(sslContext);

    delete wirelessConnectionManager;
}
