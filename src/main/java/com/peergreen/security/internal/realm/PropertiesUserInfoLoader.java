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

import static java.lang.String.format;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashService;

/**
 * User: guillaume
 * Date: 25/03/13
 * Time: 11:18
 *
 * users.properties
 * <pre>
 *     UsersProperty ::= UserName + ' ' + Value
 *     UserName ::= STRING
 *     Value ::= '{' + Descriptor + '}' + Input
 *     Descriptor ::= Encryption + '+' + Encoding
 *                ::= Encryption
 *     Encryption ::= STRING
 *     Encoding ::= STRING
 *     Input ::= STRING
 * </pre>
 *
 * groups.properties
 * <pre>
 *     GroupProperty ::= UserName + ' ' + Groups
 *     UserName ::= STRING
 *     Groups ::= Group + ',' + Groups
 *            ::= Group
 *     Group ::= STRING
 * </pre>
 */
public class PropertiesUserInfoLoader {

    private static final Pattern HASH_PATTERN = Pattern.compile("\\{(.*)\\}(.*)");
    private static final Pattern DESC_PATTERN = Pattern.compile("(.*)\\+(.*)|(.*)");

    private final HashServiceFinder finder;

    public PropertiesUserInfoLoader(HashServiceFinder finder) {
        this.finder = finder;
    }

    public Set<UserInfo> load(Properties users, Properties groups) {

        Map<String, UserInfo> loaded = new HashMap<>();

        for (String name : users.stringPropertyNames()) {
            try {
                Hash hash = createHash(users.getProperty(name));
                loaded.put(name, new UserInfo(name, hash));
            } catch (Exception e) {
                // Log something like
                // Users '%s' could not be created because %s (e.getMessage)
            }
        }

        for (String name : groups.stringPropertyNames()) {
            UserInfo info = loaded.get(name);
            if (info != null) {
                String[] roles = groups.getProperty(name).split(",");
                for (String role : roles) {
                    info.addRole(role.trim());
                }
            }
        }

        // Need a new instance to be "detached" from the Map
        // Keep it sorted (useful for testing)
        return new TreeSet<>(loaded.values());

    }

    private Hash createHash(String input) throws Exception {

        Matcher matcher = HASH_PATTERN.matcher(input);
        if (!matcher.matches()) {
            throw new Exception(format(
                    "property value ('%s') do not respect the expected format '%s'",
                    input,
                    HASH_PATTERN.pattern()));
        }

        String descriptor = matcher.group(1);
        String hashed = matcher.group(2);

        Matcher descriptorMatcher = DESC_PATTERN.matcher(descriptor);
        if (!descriptorMatcher.matches()) {
            throw new Exception(format(
                    "hash descriptor ('%s') do not respect the expected format '%s'",
                    descriptor,
                    DESC_PATTERN.pattern()));
        }

        HashService service = null;
        String encryption = descriptorMatcher.group(3);

        if (encryption == null) {
            encryption = descriptorMatcher.group(1);
        }

        service = finder.find(encryption);
        if (service == null) {
            throw new Exception(format(
                    "HashService for '%s' encryption is missing",
                    encryption));
        }

        // Read encoder (if any)
        String encoder = descriptorMatcher.group(2);

        return service.build(encoder, hashed);

    }



}
