#include "str.h"
#include <iostream>

void str_split(const std::string str, std::string &left, std::string &right, const char c) {
 
  std::string temp;
  std::stringstream stream;
  stream << c;
  temp = stream.str();
  std::string pattern = "([[:alpha:]]+)" + temp + "(.*)";
  std::regex r(pattern);
  std::smatch results;
  std::regex_search(str, results, r);
  left = results.str(1);
  right = results.str(2);
  //std::cout << results.str(0) << std::endl;
  //std::cout << results.str(1) << std::endl;
  //std::cout << results.str(2) << std::endl;
}