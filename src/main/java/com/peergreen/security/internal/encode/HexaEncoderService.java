/*
 * Copyright 2013 Peergreen SAS
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.peergreen.security.internal.encode;

import java.math.BigInteger;
import java.util.Arrays;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.StaticServiceProperty;

import com.peergreen.security.encode.EncoderService;

/**
 * User: guillaume
 * Date: 21/03/13
 * Time: 10:27
 */
@Component
@Provides(
        properties = @StaticServiceProperty(
                name = EncoderService.ENCODER_FORMAT,
                value = "{hex, hexa, hexadecimal}",
                type = "java.lang.String[]"
        )
)
public class HexaEncoderService implements EncoderService {
    @Override
    public String encode(byte[] value) {
        BigInteger bi = new BigInteger(1, value);
        return String.format("%0" + (value.length * 2) + "x", bi);
    }

    @Override
    public byte[] decode(String value) {
        // This is an hex value (16 bits)
        BigInteger bi = new BigInteger(value, 16);
        byte[] signed = bi.toByteArray();
        if (value.startsWith("00")) {
            return signed;
        }
        // Remove the sign bit
        return Arrays.copyOfRange(signed, 1, signed.length);
    }
}
