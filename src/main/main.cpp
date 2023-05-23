#include "Server.h"

int main()
{
	Server server("192.168.0.102", 80, std::cout);
	server.start();

	return 0;
}
