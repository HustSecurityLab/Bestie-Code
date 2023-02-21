project(mitraStar)

set(CMAKE_CXX_STANDARD 14)

include_directories(. /usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)

link_libraries(-lcrypto -lssl)

add_executable(mitraStar
        main.cpp
        mitraStar.cpp
        mitraStar.h
        sse_benchmark.cpp
        sse_benchmark.h)
