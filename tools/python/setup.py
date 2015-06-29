# This file is copyright 2015 by Guillaume Roguez <yomgui1 AT gmail DOT com>
# A Python3 wrapper to access to OpenDHT API
# This wrapper is written for Cython 0.22
#
# This file is part of OpenDHT Python Wrapper.
#
#    OpenDHT Python Wrapper is free software:  you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    OpenDHT Python Wrapper is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with OpenDHT Python Wrapper. If not, see <http://www.gnu.org/licenses/>.
#

from distutils.core import setup, Extension
from Cython.Build import cythonize

setup(name="opendht",
      version="0.1",
      description="Cython generated wrapper for opendht",
      author="Guillaume Roguez",
      license="GPLv3",
      ext_modules = cythonize(Extension(
          "opendht",
          ["opendht.pyx"],
          language="c++",
          extra_compile_args=["-std=c++11"],
          extra_link_args=["-std=c++11"],
          libraries=["opendht"]
      ))
)
