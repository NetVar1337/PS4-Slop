include_guard(GLOBAL)

# slop_add_win_resources(<target> DESCRIPTION <text> MANIFEST <manifest.in>)
#
# Configures <manifest.in> (assemblyIdentity version from PROJECT_VERSION) and
# a resource script carrying that manifest plus a VERSIONINFO block into the
# target's binary dir, then compiles it into <target>. The exe name comes from
# the target's OUTPUT_NAME (or the target name).
function(slop_add_win_resources target)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "DESCRIPTION;MANIFEST" "")
    if(NOT arg_DESCRIPTION OR NOT arg_MANIFEST)
        message(FATAL_ERROR "slop_add_win_resources: DESCRIPTION and MANIFEST are required")
    endif()
    get_target_property(_name ${target} OUTPUT_NAME)
    if(NOT _name)
        set(_name ${target})
    endif()

    set(_out "${CMAKE_CURRENT_BINARY_DIR}/${target}_res")
    get_filename_component(_manifest_name "${arg_MANIFEST}" NAME)
    string(REGEX REPLACE "\\.in$" "" _manifest_name "${_manifest_name}")
    configure_file("${arg_MANIFEST}" "${_out}/${_manifest_name}" @ONLY)

    set(SLOP_RC_MANIFEST "${_out}/${_manifest_name}")
    set(SLOP_RC_DESCRIPTION "${arg_DESCRIPTION}")
    set(SLOP_RC_NAME "${_name}")
    configure_file("${PROJECT_SOURCE_DIR}/cmake/win_resources.rc.in" "${_out}/${target}.rc" @ONLY)

    target_sources(${target} PRIVATE "${_out}/${target}.rc")
    # the manifest is embedded as RT_MANIFEST by the .rc, keep the linker's own
    # manifest machinery out of it entirely (CMP0090 NEW)
    target_link_options(${target} PRIVATE "/MANIFEST:NO")
endfunction()
