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

import javax.security.auth.Subject;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Property;
import org.apache.felix.ipojo.annotations.Provides;

import com.peergreen.security.UsernamePasswordAuthenticateService;
import com.peergreen.security.AutoLoginService;

/**
 * User: guillaume
 * Date: 18/03/13
 * Time: 15:09
 */
@Component
@Provides
public class UsernamePasswordAutoLoginService implements AutoLoginService {

    private String username;
    private String password;
    private UsernamePasswordAuthenticateService authenticateService;

    @Property(mandatory = true, name = "username")
    public void setUsername(String username) {
        this.username = username;
    }

    @Property(mandatory = true, name = "password")
    public void setPassword(String password) {
        this.password = password;
    }

    @Bind
    public void bindAuthenticateService(UsernamePasswordAuthenticateService authenticateService) {
        this.authenticateService = authenticateService;
    }

    @Override
    public Subject authenticate() {
        return authenticateService.authenticate(username, password);
    }
}
