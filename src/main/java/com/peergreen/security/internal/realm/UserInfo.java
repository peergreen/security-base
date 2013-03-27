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

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

import com.peergreen.security.hash.Hash;

/**
 * User: guillaume
 * Date: 19/03/13
 * Time: 17:20
 */
public class UserInfo implements Comparable<UserInfo> {
    private final String username;
    private final Hash hashedPassword;
    private final Set<String> roles = new TreeSet<>();

    public UserInfo(String username, Hash hashedPassword) {
        this.username = username;
        this.hashedPassword = hashedPassword;
    }

    public String getUsername() {
        return username;
    }

    public Hash getHashedPassword() {
        return hashedPassword;
    }

    public Set<String> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public void addRole(String role) {
        roles.add(role);
    }

    public void removeRole(String role) {
        roles.remove(role);
    }

    @Override
    public int compareTo(UserInfo o) {
        return username.compareTo(o.username);
    }
}
