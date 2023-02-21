project(fides)

set(CMAKE_CXX_STANDARD 14)

include_directories(. /usr/local/opt/openssl/include /usr/local/opt/gmp/include)
link_directories(/usr/local/opt/openssl/lib /usr/local/opt/gmp/lib)

link_libraries(-lcrypto -lssl -lgmp)

add_executable(fides
        fides.cpp
        fides.h
        main.cpp
        sophos.cpp
        sophos.h
        sse_benchmark.cpp
        sse_benchmark.h
        trapdoor_permutation.cpp
        trapdoor_permutation.h)
