# - Try to find readline, a library for easy editing of command lines.
# Variables used by this module:
#  READLINE_ROOT_DIR     - Readline root directory
# Variables defined by this module:
#  READLINE_FOUND        - system has Readline
#  READLINE_INCLUDE_DIR  - the Readline include directory (cached)
#  READLINE_INCLUDE_DIRS - the Readline include directories
#                          (identical to READLINE_INCLUDE_DIR)
#  READLINE_LIBRARY      - the Readline library (cached)
#  READLINE_LIBRARIES    - the Readline library plus the libraries it 
#                          depends on

# Copyright (C) 2009
# ASTRON (Netherlands Institute for Radio Astronomy)
# P.O.Box 2, 7990 AA Dwingeloo, The Netherlands
#
# This program is free software; you can redistribute it and/or modify
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.
#
# $Id: FindReadline.cmake 15228 2010-03-16 09:27:26Z loose $

if(NOT READLINE_FOUND)

  find_path(READLINE_INCLUDE_DIR readline/readline.h
    HINTS ${READLINE_ROOT_DIR} PATH_SUFFIXES include)
  find_library(READLINE_LIBRARY readline
    HINTS ${READLINE_ROOT_DIR} PATH_SUFFIXES lib)
  find_library(NCURSES_LIBRARY ncurses)   # readline depends on libncurses
  mark_as_advanced(READLINE_INCLUDE_DIR READLINE_LIBRARY NCURSES_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Readline DEFAULT_MSG
    READLINE_LIBRARY NCURSES_LIBRARY READLINE_INCLUDE_DIR)

  set(READLINE_INCLUDE_DIRS ${READLINE_INCLUDE_DIR})
  set(READLINE_LIBRARIES ${READLINE_LIBRARY} ${NCURSES_LIBRARY})

endif(NOT READLINE_FOUND)
