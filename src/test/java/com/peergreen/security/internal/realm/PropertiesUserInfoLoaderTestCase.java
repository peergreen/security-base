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

package com.peergreen.security.internal.realm;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashService;

/**
 * User: guillaume
 * Date: 25/03/13
 * Time: 11:32
 */
public class PropertiesUserInfoLoaderTestCase {

    @Mock
    private HashService hasher;

    @Mock
    private Hash hash;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testBasicUserLoading() throws Exception {
        PropertiesUserInfoLoader loader = new PropertiesUserInfoLoader(new HashServiceFinder() {
            @Override
            public HashService find(String encryption) {
                return hasher;
            }
        });
        when(hasher.build(null, "s3cr3t")).thenReturn(hash);

        Properties u = new Properties();
        u.setProperty("guillaume", "{plain}s3cr3t");

        Properties g = new Properties();
        g.setProperty("admin", "guillaume");
        g.setProperty("platform", "guillaume");

        Collection<UserInfo> infos = loader.load(u, g);

        assertEquals(infos.size(), 1);
        UserInfo user = infos.iterator().next();

        assertEquals(user.getLogin(), "guillaume");
        assertEquals(user.getRoles().size(), 2);
        assertTrue(user.getRoles().contains("admin"));
        assertTrue(user.getRoles().contains("platform"));

    }

    @Test
    public void testUserLoadingWithEncodingSpecified() throws Exception {
        PropertiesUserInfoLoader loader = new PropertiesUserInfoLoader(new HashServiceFinder() {
            @Override
            public HashService find(String encryption) {
                return hasher;
            }
        });
        when(hasher.build("text", "s3cr3t")).thenReturn(hash);

        Properties u = new Properties();
        u.setProperty("guillaume", "{plain+text}s3cr3t");

        Properties g = new Properties();
        g.setProperty("admin", "guillaume");
        g.setProperty("platform", "guillaume");

        Collection<UserInfo> infos = loader.load(u, g);

        assertEquals(infos.size(), 1);
        UserInfo user = infos.iterator().next();

        assertEquals(user.getLogin(), "guillaume");
        assertEquals(user.getRoles().size(), 2);
        assertTrue(user.getRoles().contains("admin"));
        assertTrue(user.getRoles().contains("platform"));

    }


    @Test
    public void testMultipleUserLoading() throws Exception {
        PropertiesUserInfoLoader loader = new PropertiesUserInfoLoader(new HashServiceFinder() {
            @Override
            public HashService find(String encryption) {
                return hasher;
            }
        });
        when(hasher.build(null, "s3cr3t")).thenReturn(hash);
        when(hasher.build("text", "|o1|5/\\73")).thenReturn(hash);

        Properties u = new Properties();
        u.setProperty("guillaume", "{plain}s3cr3t");
        u.setProperty("florent", "{plain+text}|o1|5/\\73"); // l33t :)

        Properties g = new Properties();
        g.setProperty("admin", "guillaume, florent");
        g.setProperty("platform", "guillaume");

        Collection<UserInfo> infos = loader.load(u, g);

        assertEquals(infos.size(), 2);
        Iterator<UserInfo> iterator = infos.iterator();
        UserInfo user = iterator.next();

        assertEquals(user.getLogin(), "florent");
        assertEquals(user.getRoles().size(), 1);
        assertTrue(user.getRoles().contains("admin"));

        UserInfo user2 = iterator.next();

        assertEquals(user2.getLogin(), "guillaume");
        assertEquals(user2.getRoles().size(), 2);
        assertTrue(user2.getRoles().contains("admin"));
        assertTrue(user2.getRoles().contains("platform"));

    }

}
