cmake_minimum_required(VERSION 3.16)

project(net_image_extractor LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PcapPlusPlus REQUIRED)

add_executable(${CMAKE_PROJECT_NAME} main.cpp
			 timgextractor.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC PcapPlusPlus::Pcap++)
