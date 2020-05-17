cmake_minimum_required(VERSION 3.16)

project(autoban)
include_directories(../unrealircd-5.0.4/include)

add_library(autoban STATIC m_autoban.c)