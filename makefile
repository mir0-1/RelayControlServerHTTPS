all: remote

OUTPUT_NAME := server.out
COMPILER = g++ -std=c++11 -g
CONFIG = -L/usr/lib/openssl `pkg-config --cflags --libs glib-2.0 libnm` -lssl -lcrypto
BUILD = $(COMPILER) $^ $(CONFIG) -o $(OUTPUT_NAME)

local: src/main/*.cpp ../SimpleKeyValueParseLib/src/main/*.cpp ../HttpLibrary/src/*.cpp ../RelayLibrary/RelayController.cpp ../I2CLib/i2c.cpp ../VoltageLibrary/VoltageReader.cpp ../WirelessLibrary/WirelessConnectionManager.cpp ../EventManager/EventManager.cpp
		make clean
		$(BUILD)

remote: src/main/*.cpp ../SimpleKeyValueParseLib/src/main/*.cpp ../HttpLibrary/src/*.cpp ../RelayLibrary/RelayController.cpp ../I2CLib/i2c.cpp ../VoltageLibrary/VoltageReader.cpp ../WirelessLibrary/WirelessConnectionManager.cpp ../EventManager/EventManager.cpp
		make clean
		git pull
		$(BUILD)

clean:
	rm -f $(OUTPUT_NAME)
