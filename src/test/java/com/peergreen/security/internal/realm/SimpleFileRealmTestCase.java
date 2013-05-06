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

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Arrays;
import javax.security.auth.Subject;

import org.testng.annotations.Test;

import com.peergreen.security.internal.hash.plain.PlainHashService;

/**
 * User: guillaume
 * Date: 25/03/13
 * Time: 12:02
 */
public class SimpleFileRealmTestCase {

    @Test
    public void testAuthenticationWithSuccess() throws Exception {
        SimpleFileRealm realm = new SimpleFileRealm(getRootFile(), new PlainHashService(), null);
        realm.registerHashService(Arrays.asList("plain"), new PlainHashService());
        realm.start();

        Subject subject = realm.authenticate("admin", "peergreen");
        assertNotNull(subject);
        assertTrue(subject.isReadOnly());

    }

    private File getRootFile() throws MalformedURLException, URISyntaxException {
        return new File(getClass().getResource("/metadata.xml").toURI().toURL().getFile()).getParentFile();
    }

    @Test
    public void testAuthenticationWithFailureWrongPassword() throws Exception {

        SimpleFileRealm realm = new SimpleFileRealm(getRootFile(), new PlainHashService(), null);
        realm.registerHashService(Arrays.asList("plain"), new PlainHashService());
        realm.start();

        Subject subject = realm.authenticate("admin", "wrong");
        assertNull(subject);

    }

    @Test
    public void testAuthenticationWithFailureNoUserDefined() throws Exception {

        SimpleFileRealm realm = new SimpleFileRealm(getRootFile(), new PlainHashService(), null);
        realm.registerHashService(Arrays.asList("plain"), new PlainHashService());
        realm.start();

        Subject subject = realm.authenticate("missing", "wrong");
        assertNull(subject);

    }
}
