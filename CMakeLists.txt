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

INCLUDE_DIRECTORIES(
  ./log
)

add_subdirectory(log)

add_executable(
  myminiftp
  #src_/Timestamp_unittest.cc
  src_/Logging_test.cc
)


target_link_libraries(
  myminiftp
  log
)
