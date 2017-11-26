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


INCLUDE_DIRECTORIES(
  /home/pi/muduo-0.9.1
  ./lib
)



add_executable(
  myminiftp
  lib/inet_sockets.cc
  lib/error_functions.cc
  src_/main.cc
  )


target_link_libraries(
  myminiftp
  /home/pi/build/debug/lib/libmuduo_base.a
  pthread
  crypt
)