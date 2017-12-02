cmake_minimum_required(VERSION 3.6)



#INCLUDE_DIRECTORIES(
#  ./lib
#)

#add_subdirectory(lib)



#add_executable(
#  miniftp
#  src/main.c
#  src/session.c
#  src/privparent.c
#  src/ftpproto.c
#  src/str.c
#  src/tunable.c
#  src/parseconf.c
#  src/privsock.c
#)

#target_link_libraries(
#  miniftp
#  utils
#  crypt
#)


SET( CMAKE_BUILD_TYPE Debug )

set (CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(
  /home/pi/muduo-0.9.1
  ./lib
)



add_executable(
  myminiftp
  lib/rdwrn.cxx
  lib/read_line.cxx
  lib/inet_sockets.cc
  lib/error_functions.cc
  src_/main.cxx
  src_/session.cxx
  src_/unix_socket.cxx
  src_/ftp_service.cxx
  src_/str.cxx
  )


target_link_libraries(
  myminiftp
  /home/pi/build/debug/lib/libmuduo_base.a
  pthread
  crypt
)