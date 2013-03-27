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

package com.peergreen.security.internal.hash.plain;

import java.util.Arrays;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.StaticServiceProperty;

import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashException;
import com.peergreen.security.hash.HashService;

/**
 * User: guillaume
 * Date: 22/03/13
 * Time: 14:55
 */
@Component
@Provides(
        properties = @StaticServiceProperty(
                name = HashService.HASH_NAME_PROPERTY,
                value = "plain",
                type = "java.lang.String"
        )
)
public class PlainHashService implements HashService {
    @Override
    public Hash generate(String clear) {
        return new PlainHash(clear);
    }

    @Override
    public Hash generate(String clear, byte[] salt) {
        return new PlainHash(clear);
    }

    @Override
    public Hash build(String encoder, String encoded) throws HashException {
        // Do not require decoding since we simply read the String value
        return new PlainHash(encoded);
    }

    @Override
    public boolean validate(String clear, Hash hash) {
        return Arrays.equals(new PlainHash(clear).getHashedValue(), hash.getHashedValue());
    }
}
