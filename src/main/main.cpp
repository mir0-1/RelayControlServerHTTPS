#include "Server.h"

int main(int argc, char *argv[])
{
	if (argc > 1)
	{
		Server server(argv[1], 80, std::cout);
		server.start();
	}
	else
	{
		Server server("192.168.0.103", 80, std::cout);
		server.start();
	}

	return 0;
}
