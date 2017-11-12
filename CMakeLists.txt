cmake_minimum_required(VERSION 3.6)



INCLUDE_DIRECTORIES(
  ./lib
)

add_subdirectory(lib)



add_executable(
  miniftp
  src/main.c
  src/session.c
  src/privparent.c
  src/ftpproto.c
  src/str.c
  src/tunable.c
  src/parseconf.c
)

target_link_libraries(
  miniftp
  utils
  crypt
)
