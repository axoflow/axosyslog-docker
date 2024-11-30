set(SYSLOG_NG_FX_SOURCES
    syslog-ng-fx.c
)

add_executable(syslog-ng-fx ${SYSLOG_NG_FX_SOURCES})
target_link_libraries(syslog-ng-fx PRIVATE
    syslog-ng
    secret-storage
    GLib::GLib
    ${RESOLV_LIBS})
target_include_directories(syslog-ng-fx PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS syslog-ng-fx RUNTIME DESTINATION sbin)
