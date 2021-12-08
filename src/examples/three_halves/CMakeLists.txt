
add_executable(three_halves_test three_halves_test.cpp common/three_halves.cpp)
target_link_libraries(three_halves_test ABY::aby ENCRYPTO_utils::encrypto_utils)
