project(januspp_with_256bits_tag)

set(CMAKE_CXX_STANDARD 14)

include_directories(. /usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)
link_libraries(-lcrypto -lssl)

add_executable(januspp_with_256bits_tag
        constrained_prf.cpp
        constrained_prf.h
        diana.cpp
        diana.h
        januspp.cpp
        januspp.h
        main.cpp
        pun_encryption.cpp
        pun_encryption.h
        pun_prf.cpp
        pun_prf.h
        sse_benchmark.cpp
        sse_benchmark.h)
