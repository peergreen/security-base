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

package com.peergreen.security.internal.hash.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.osgi.framework.ServiceReference;

/**
 * User: guillaume
 * Date: 22/03/13
 * Time: 15:55
 */
public class References {

    private References() {}

    public static List<String> getMultiValuedProperty(ServiceReference<?> reference, String propertyName) {

        Object property = reference.getProperty(propertyName);
        if (property instanceof String) {
            return Collections.singletonList((String) property);
        } else if (property instanceof String[]) {
            return Arrays.asList((String[]) property);
        }

        return null;
    }

}
