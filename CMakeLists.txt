cmake_minimum_required(VERSION 3.4)
project(my_AES C)
add_subdirectory(lib)

add_executable(my_AES main.c)

target_link_libraries(my_AES PUBLIC aes)

