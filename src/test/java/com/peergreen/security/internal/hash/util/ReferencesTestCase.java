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

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.ServiceReference;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * User: guillaume
 * Date: 25/03/13
 * Time: 11:54
 */
public class ReferencesTestCase {

    @Mock
    private ServiceReference<?> reference;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testEmptyReference() throws Exception {
        assertNull(References.getMultiValuedProperty(reference, "Property"));
    }

    @Test
    public void testSingleValuedReference() throws Exception {
        when(reference.getProperty("Property")).thenReturn("Value");
        assertContentEquals(References.getMultiValuedProperty(reference, "Property"), "Value");
    }

    @Test
    public void testMultiValuedReference() throws Exception {
        when(reference.getProperty("Property")).thenReturn(new String [] {"A", "B", "C"});
        assertContentEquals(References.getMultiValuedProperty(reference, "Property"), "A", "B", "C");
    }

    private static void assertContentEquals(Iterable<String> values, String... expected) {
        List<String> missing = new ArrayList<>(Arrays.asList(expected));
        for (String value : values) {
            missing.remove(value);
        }

        assertTrue(missing.isEmpty());
    }
}
