"""
"""

# Created on 2021
#
# Author: Thomas Lärm
# Based in large parts on work by Giovanni Cannata for https://github.com/cannatag/ldap3
#
# Copyright 2021 Thomas Lärm
#
# This file is part of clap.
#
# clap is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# clap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with clap in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

def compute_ldap_message_size(data):
    """
    Compute LDAP Message size according to BER definite length rules
    Returns -1 if too few data to compute message length
    """
    if isinstance(data, str):  # fix for Python 2, data is string not bytes
        data = bytearray(data)  # Python 2 bytearray is equivalent to Python 3 bytes

    ret_value = -1
    if len(data) > 2:
        if data[1] <= 127:  # BER definite length - short form. Highest bit of byte 1 is 0, message length is in the last 7 bits - Value can be up to 127 bytes long
            ret_value = data[1] + 2
        else:  # BER definite length - long form. Highest bit of byte 1 is 1, last 7 bits counts the number of following octets containing the value length
            bytes_length = data[1] - 128
            if len(data) >= bytes_length + 2:
                value_length = 0
                cont = bytes_length
                for byte in data[2:2 + bytes_length]:
                    cont -= 1
                    value_length += byte * (256 ** cont)
                ret_value = value_length + 2 + bytes_length

    return ret_value