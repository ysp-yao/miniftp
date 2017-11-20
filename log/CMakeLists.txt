cmake_minimum_required(VERSION 3.6)

add_library(
  log 
  SHARED
  Timestamp.cc
  TimeZone.cc
  ThreadPool.cc
  Thread.cc
  Logging.cc
  LogStream.cc
  LogFile.cc
  CountDownLatch.cc
  Condition.cc
  Date.cc
  Exception.cc
  FileUtil.cc
)

set_target_properties(log PROPERTIES output_name "log")

