cmake_minimum_required(VERSION 3.6)

add_library(
  utils 
  SHARED 
  error_functions.c
  get_num.c
  inet_sockets.c
  rdwrn.c
  read_line.c
)

set_target_properties(utils PROPERTIES output_name "utils")

