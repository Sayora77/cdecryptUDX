ifeq ($(OS),Windows_NT)
  EXE := .exe
else
  EXE :=
endif

LIB_DIR = D:/GitHub/_lib/curl-8.19.0_8-win64-mingw

# --- wuptool ---
BIN  = wuptool
OBJ  = wuptool.o cpack.o util.o aes.o sha1.o
DEP  = wuptool.d cpack.d util.d aes.d sha1.d

# --- wiiudownload ---
BIN2 = wiiudownload
OBJ2 = wiiudownload.o util.o aes.o sha1.o
DEP2 = wiiudownload.d util.d aes.d sha1.d

# -Wno-sequence-point because *dst++ = dst[-d]; is only ambiguous for people who don't know how CPUs work.
CFLAGS     = -std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -Wno-sequence-point \
             -Wno-unknown-pragmas -Wno-multichar -UNDEBUG -DAES_ROM_TABLES -D_GNU_SOURCE -O2
CFLAGS_DL  = $(CFLAGS) -DCURL_STATICLIB -I$(LIB_DIR)/include

ifeq ($(OS),Windows_NT)
  LDFLAGS    = -s -municode
  # Libraries listed after object files — GNU ld requires this order
  LIBS_DL    = \
    $(LIB_DIR)/lib/libcurl.a \
    $(LIB_DIR)/lib/libssl.a \
    $(LIB_DIR)/lib/libcrypto.a \
    $(LIB_DIR)/lib/libssh2.a \
    $(LIB_DIR)/lib/libnghttp2.a \
    $(LIB_DIR)/lib/libnghttp3.a \
    $(LIB_DIR)/lib/libngtcp2.a \
    $(LIB_DIR)/lib/libngtcp2_crypto_libressl.a \
    $(LIB_DIR)/lib/libbrotlidec.a \
    $(LIB_DIR)/lib/libbrotlicommon.a \
    $(LIB_DIR)/lib/libpsl.a \
    $(LIB_DIR)/lib/libzstd.a \
    $(LIB_DIR)/lib/libz.a \
    -lws2_32 -lwldap32 -lcrypt32 -lbcrypt -lsecur32 -liphlpapi
else
  LDFLAGS    = -s
  LIBS_DL    = -lcurl -lz
endif

.PHONY: all clean

all: $(BIN)$(EXE) $(BIN2)$(EXE)

clean:
	$(RM) $(BIN)$(EXE) $(BIN2)$(EXE) wuptool.o cpack.o wiiudownload.o util.o aes.o sha1.o $(DEP) $(DEP2)

$(BIN)$(EXE): $(OBJ)
	@echo [L] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(BIN2)$(EXE): $(OBJ2)
	@echo [L] $@
	@$(CC) -s -o $@ $^ $(LIBS_DL)

wiiudownload.o: wiiudownload.c
	@echo [C] $<
	@$(CC) $(CFLAGS_DL) -MMD -c -o $@ $<

%.o: %.c
	@echo [C] $<
	@$(CC) $(CFLAGS) -MMD -c -o $@ $<

-include $(DEP) $(DEP2)