#include "Server.h"
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "../../../HttpLibrary/src/HttpRequest.h"

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
    if (SSL_CTX_use_certificate_file(sslContext, "resources/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        logger << "Could not use cert file" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, "resources/key.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        logger << "Could not use key file" << std::endl;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
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

                std::string reply = responseBuilder
                                        .setStatusCode(HttpStatusCode::OK)
                                        .setContentType(HttpContentType::HTML)
                                        .setRawBody("<html><b>Hello world!</b></html>")
                                        .build();

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
