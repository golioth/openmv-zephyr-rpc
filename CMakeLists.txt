if (CONFIG_OPENMV_RPC)
  zephyr_include_directories(include)
  zephyr_library_sources(openmv_rpc.c)
endif()
