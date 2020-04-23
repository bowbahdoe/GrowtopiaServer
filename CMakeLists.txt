cmake_minimum_required(VERSION 3.15)
project(GrowtopiaServer)

set(CMAKE_CXX_STANDARD 14)

include_directories("enet server test")
include_directories("enet server test/crypt_blowfish")
include_directories("enet server test/enet")
include_directories("enet server test/enet2/include")
include_directories("enet server test/enet2/include/enet")

add_executable(GrowtopiaServer
        "enet server test/crypt_blowfish/crypt.h"
        "enet server test/crypt_blowfish/crypt_blowfish.cpp"
        "enet server test/crypt_blowfish/crypt_blowfish.h"
        "enet server test/crypt_blowfish/crypt_gensalt.cpp"
        "enet server test/crypt_blowfish/crypt_gensalt.h"
        "enet server test/crypt_blowfish/ow-crypt.cpp"
        "enet server test/crypt_blowfish/ow-crypt.h"
        "enet server test/enet/callbacks.h"
        "enet server test/enet/enet.h"
        "enet server test/enet/list.h"
        "enet server test/enet/protocol.h"
        "enet server test/enet/time.h"
        "enet server test/enet/types.h"
        "enet server test/enet/unix.h"
        "enet server test/enet/utility.h"
        "enet server test/enet/win32.h"
        "enet server test/enet2/include/enet/callbacks.h"
        "enet server test/enet2/include/enet/enet.h"
        "enet server test/enet2/include/enet/list.h"
        "enet server test/enet2/include/enet/protocol.h"
        "enet server test/enet2/include/enet/time.h"
        "enet server test/enet2/include/enet/types.h"
        "enet server test/enet2/include/enet/unix.h"
        "enet server test/enet2/include/enet/utility.h"
        "enet server test/enet2/include/enet/win32.h"
        "enet server test/enet2/callbacks.c"
        "enet server test/enet2/compress.c"
        "enet server test/enet2/host.c"
        "enet server test/enet2/list.c"
        "enet server test/enet2/packet.c"
        "enet server test/enet2/peer.c"
        "enet server test/enet2/protocol.c"
        "enet server test/enet2/unix.c"
        "enet server test/enet2/win32.c"
        "enet server test/bcrypt.cpp"
        "enet server test/bcrypt.h"
        "enet server test/enet server test.cpp"
        "enet server test/GTAPI.h"
        "enet server test/json.hpp"
        "enet server test/stdafx.cpp"
        "enet server test/stdafx.h"
        "enet server test/targetver.h")
