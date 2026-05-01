CXX      := g++
# C++17 for structured bindings and std::string_view if needed later.
# -Wall -Wextra: catch common bugs at compile time.
# -g: include debug symbols for GDB.
CXXFLAGS := -std=c++17 -Wall -Wextra -g

# OpenSSL provides EVP (hashing) and RAND_bytes (salt generation).
LDFLAGS  := -lssl -lcrypto

TARGET   := hashtool
SRCDIR   := src
SOURCES  := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS  := $(SOURCES:.cpp=.o)

# ── Build targets ─────────────────────────────────────────────────────────────

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o $(TARGET) hashes.db passwords.db *.log
