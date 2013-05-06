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

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

/**
 * User: guillaume
 * Date: 21/03/13
 * Time: 11:04
 */
public class HexaEncoderServiceTestCase {
    @Test
    public void testToHexadecimal() throws Exception {
        HexaEncoderService converter = new HexaEncoderService();
        byte[] bytes = { (byte) 0xa0, (byte)0xb7, (byte)0x07, (byte)0x08};
        assertEquals(converter.encode(bytes), "a0b70708");
    }

    @Test
    public void testToHexadecimalWithLeadingZeros() throws Exception {
        HexaEncoderService converter = new HexaEncoderService();
        byte[] bytes = { (byte) 0x00, (byte)0x00, (byte)0x07, (byte)0x08};
        assertEquals(converter.encode(bytes), "00000708");
    }

    @Test
    public void testToHexadecimalWithTrailingZeros() throws Exception {
        HexaEncoderService converter = new HexaEncoderService();
        byte[] bytes = { (byte) 0xa0, (byte)0xb7, (byte)0x00, (byte)0x00};
        assertEquals(converter.encode(bytes), "a0b70000");
    }

    @Test
    public void testFromHexadecimal() throws Exception {
        HexaEncoderService converter = new HexaEncoderService();
        byte[] expected = { (byte) 0xa0, (byte)0xb7, (byte)0x07, (byte)0x08};
        byte[] bytes = converter.decode("a0b70708");
        assertEquals(bytes, expected);
    }

    @Test
    public void testFromHexadecimalWithLeadingZeros() throws Exception {
        HexaEncoderService converter = new HexaEncoderService();
        byte[] expected = { (byte)0x07, (byte)0x08 };
        byte[] bytes = converter.decode("00000708");
        assertEquals(bytes, expected);
    }
}
