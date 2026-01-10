CXX = g++
CXXFLAGS = -O2 -Wall -Wextra
LDFLAGS = -static
LIBS = -lWtsApi32 -lUserenv -lntdll -ladvapi32 -lgdi32 -lcomctl32 -lMsftedit -lcomdlg32 -luuid -lole32

TARGET = WinSudo
SRC = WinSudo.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LIBS)

clean:
	del /Q $(TARGET).exe 2>nul

.PHONY: clean
