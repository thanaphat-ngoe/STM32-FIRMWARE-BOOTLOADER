cmake_minimum_required(VERSION 3.22)

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Define the build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# --- NEW: Define the selection variable ---
set(FIRMWARE_SECTION "Bootloader" CACHE STRING "Select firmware section: Bootloader or Application")
set_property(CACHE FIRMWARE_SECTION PROPERTY STRINGS "Bootloader" "Application")

# Set the project name dynamically based on selection
set(CMAKE_PROJECT_NAME STM32L053R8-FIRMWARE-${FIRMWARE_SECTION})

# Enable compile command to ease indexing with e.g. clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Core project settings
project(${CMAKE_PROJECT_NAME})
message("Build type: " ${CMAKE_BUILD_TYPE})
message("Building section: " ${FIRMWARE_SECTION})

# Enable CMake support for ASM and C languages
enable_language(C ASM)

# Create an executable object type
add_executable(${CMAKE_PROJECT_NAME})

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)

# --- NEW: Apply the correct linker script ---
if(FIRMWARE_SECTION STREQUAL "Bootloader")
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/Bootloader/BOOTLOADER_STM32L053XX_FLASH.ld)
elseif(FIRMWARE_SECTION STREQUAL "Application")
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/Application/APPLICATION_STM32L053XX_FLASH.ld)
endif()

# Apply the linker script exclusively to this executable
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -T${LINKER_SCRIPT})

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE)

# Add include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE)

# Add project symbols (macros)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE)

# Remove wrong libob.a library dependency when using cpp files
list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_LIBRARIES ob)

# Add linked libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    stm32cubemx
)
