/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "base64.h"

#include <cstdint>
#include <cstdlib>

/* Mainly based on the following stackoverflow question:
 * http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 */
static const char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static const size_t mod_table[] = { 0, 2, 1 };

char *base64_encode(const uint8_t *input, size_t input_length,
                             char *output, size_t *output_length)
{
    size_t i, j;
    size_t out_sz = *output_length;
    *output_length = 4 * ((input_length + 2) / 3);
    if (out_sz < *output_length || output == nullptr)
        return nullptr;

    for (i = 0, j = 0; i < input_length; ) {
        uint8_t octet_a = i < input_length ? input[i++] : 0;
        uint8_t octet_b = i < input_length ? input[i++] : 0;
        uint8_t octet_c = i < input_length ? input[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        output[*output_length - 1 - i] = '=';

    return output;
}

uint8_t *base64_decode(const char *input, size_t input_length,
                             uint8_t *output, size_t *output_length)
{
    size_t i, j;
    uint8_t decoding_table[256];

    uint8_t c;
    for (c = 0; c < 64; c++)
        decoding_table[static_cast<int>(encoding_table[c])] = c;

    if (input_length % 4 != 0 || input_length < 2)
        return nullptr;

    size_t out_sz = *output_length;
    *output_length = input_length / 4 * 3;
    if (input[input_length - 1] == '=')
        (*output_length)--;
    if (input[input_length - 2] == '=')
        (*output_length)--;

    if (out_sz < *output_length || output == nullptr)
        return nullptr;

    for (i = 0, j = 0; i < input_length;) {
        uint8_t sextet_a = input[i] == '=' ? 0 & i++
            : decoding_table[static_cast<int>(input[i++])];
        uint8_t sextet_b = input[i] == '=' ? 0 & i++
            : decoding_table[static_cast<int>(input[i++])];
        uint8_t sextet_c = input[i] == '=' ? 0 & i++
            : decoding_table[static_cast<int>(input[i++])];
        uint8_t sextet_d = input[i] == '=' ? 0 & i++
            : decoding_table[static_cast<int>(input[i++])];

        uint32_t triple = (sextet_a << 3 * 6) +
                          (sextet_b << 2 * 6) +
                          (sextet_c << 1 * 6) +
                          (sextet_d << 0 * 6);

        if (j < *output_length)
            output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length)
            output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length)
            output[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return output;
}

std::string
base64_encode(const std::vector<uint8_t>::const_iterator begin,
              const std::vector<uint8_t>::const_iterator end)
{
    size_t output_length = 4 * ((std::distance(begin, end) + 2) / 3);
    std::string out;
    out.resize(output_length);
    base64_encode(&(*begin), std::distance(begin, end),
                  &(*out.begin()), &output_length);
    out.resize(output_length);
    return out;
}


std::string
base64_encode(const std::vector<unsigned char>& str)
{
    return base64_encode(str.cbegin(), str.cend());
}

std::vector<unsigned char>
base64_decode(const std::string& str)
{
    size_t output_length = str.length() / 4 * 3 + 2;
    std::vector<uint8_t> output;
    output.resize(output_length);
    base64_decode(str.data(), str.size(), output.data(), &output_length);
    output.resize(output_length);
    return output;
}
