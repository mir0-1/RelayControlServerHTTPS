all: remote

OUTPUT_NAME := server.out
COMPILER = g++ -std=c++11
CONFIG = -L/usr/lib/openssl -lssl -lcrypto
BUILD = $(COMPILER) $^ $(CONFIG) -o $(OUTPUT_NAME)

local: src/main/*.cpp ../SimpleKeyValueParseLib/src/main/*.cpp ../HttpLibrary/src/*.cpp
		make clean
		$(BUILD)

remote: src/main/*.cpp ../SimpleKeyValueParseLib/src/main/*.cpp ../HttpLibrary/src/*.cpp
		make clean
		git pull
		$(BUILD)

clean:
	rm -f $(OUTPUT_NAME)
