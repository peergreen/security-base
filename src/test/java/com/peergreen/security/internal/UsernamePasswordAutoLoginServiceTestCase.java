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

package com.peergreen.security.internal;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

import java.security.Principal;
import javax.security.auth.Subject;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.peergreen.security.UsernamePasswordAuthenticateService;

/**
 * User: guillaume
 * Date: 18/03/13
 * Time: 16:20
 */
public class UsernamePasswordAutoLoginServiceTestCase {

    @Mock
    UsernamePasswordAuthenticateService authenticateService;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testAuthenticateSuccess() throws Exception {
        UsernamePasswordAutoLoginService autoLoginService = new UsernamePasswordAutoLoginService();
        autoLoginService.setUsername("guillaume");
        autoLoginService.setPassword("s3cr3t");
        autoLoginService.bindAuthenticateService(authenticateService);

        Subject subject = new Subject();
        subject.getPrincipals().add(new GuillaumePrincipal());
        when(authenticateService.authenticate("guillaume", "s3cr3t")).thenReturn(subject);

        Subject returned = autoLoginService.authenticate();
        assertEquals(returned, subject);

    }

    private static class GuillaumePrincipal implements Principal {

        @Override
        public String getName() {
            return "guillaume";
        }
    }
}
