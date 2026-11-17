#####
# 'PrismPathRef' Deployment:
#
# This registers the 'PrismPathRef' deployment to the build system. 
# Custom components that have not been added at the project-level should be added to 
# the list below.
#
#####

###
# Topology and Components
###

add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Top/")

# Add custom components to this specific deployment here
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Guard/")
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Proposer/")
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Vehicle/")

register_fprime_deployment(
    SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/Main.cpp"
    DEPENDS
        ${FPRIME_CURRENT_MODULE}_Top
)
