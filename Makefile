CXX = g++
CXXFLAGS = -O3 -std=c++11
TARGET = presentation
SRC = presentation.cpp
all: $(TARGET)
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
clean:
	rm -f $(TARGET)
.PHONY: all clean

