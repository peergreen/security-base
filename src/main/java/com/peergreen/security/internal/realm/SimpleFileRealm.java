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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.acl.Group;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Property;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Requires;
import org.apache.felix.ipojo.annotations.Unbind;
import org.apache.felix.ipojo.annotations.Validate;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import com.peergreen.configuration.api.ConfigRepository;
import com.peergreen.configuration.api.Configuration;
import com.peergreen.configuration.api.Read;
import com.peergreen.configuration.api.RepositoryException;
import com.peergreen.configuration.api.Resource;
import com.peergreen.configuration.api.Version;
import com.peergreen.configuration.api.VersionedResource;
import com.peergreen.configuration.api.Write;
import com.peergreen.configuration.simple.FileConfiguration;
import com.peergreen.security.UsernamePasswordAuthenticateService;
import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashService;
import com.peergreen.security.internal.hash.util.References;
import com.peergreen.security.principal.RoleGroup;
import com.peergreen.security.principal.RolePrincipal;
import com.peergreen.security.principal.UserPrincipal;

/**
 * User: guillaume
 * Date: 19/03/13
 * Time: 16:53
 *
 */
@Component
@Provides
public class SimpleFileRealm implements UsernamePasswordAuthenticateService {

    private Map<String, UserInfo> users = new HashMap<>();
    private Map<String, HashService> hashers = new HashMap<>();
    private ConfigRepository repository;
    private File baseRepository;

    public SimpleFileRealm(BundleContext bundleContext) {
        this(bundleContext.getDataFile("repository"));
    }

    public SimpleFileRealm(File baseRepository) {
        this.baseRepository = baseRepository;
    }

    @Bind(optional = false, aggregate = true)
    public void bindHashService(HashService encoder, ServiceReference<HashService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, HashService.HASH_NAME_PROPERTY);
        registerHashService(names, encoder);
    }

    public void registerHashService(List<String> names, HashService encoder) {
        for (String name : names) {
            hashers.put(name, encoder);
        }
    }

    @Unbind
    public void unbindHashService(ServiceReference<HashService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, HashService.HASH_NAME_PROPERTY);
        unregisterHashService(names);
    }

    public void unregisterHashService(List<String> names) {
        for (String name : names) {
            hashers.remove(name);
        }
    }

    private void init() throws RepositoryException {
        Write write = repository.init();
        Resource ur = new ClassRelativeResource("users.properties");
        write.pushResource("users.properties", ur);
        Resource gr = new ClassRelativeResource("groups.properties");
        write.pushResource("groups.properties", gr);

        Version defaultVersion = new Version() {
            @Override
            public String getName() {
                return "default";
            }
        };
        write.tag(defaultVersion);
        repository.setProductionVersion(defaultVersion);
    }

    @Validate
    public void start() throws Exception {

        FileConfiguration configuration = new FileConfiguration();
        configuration.setRootDirectory(baseRepository);
        repository = configuration.getRepository("security-base");
        if (repository.getProductionVersion() == null) {
            // Repository not initialized
            init();
        }
        Read read = repository.read();
        VersionedResource uresource = read.getResource("users.properties");
        VersionedResource gresource = read.getResource("groups.properties");

        PropertiesUserInfoLoader loader = new PropertiesUserInfoLoader(new HashServiceFinder() {
            @Override
            public HashService find(String encryption) {
                return hashers.get(encryption);
            }
        });

        try (InputStream uis = uresource.openStream(); InputStream gis = gresource.openStream()) {
            Properties users = new Properties();
            users.load(uis);

            Properties groups = new Properties();
            groups.load(gis);

            Collection<UserInfo> userInfos = loader.load(users, groups);

            for (UserInfo info : userInfos) {
                this.users.put(info.getUsername(), info);
            }
        } catch (IOException e) {
            // TODO If we cannot read theses file, what do we do ?
        }

    }

    @Override
    public Subject authenticate(String username, String password) {
        UserInfo info = users.get(username);
        if (info == null) {
            return null;
        }

        Hash reference = info.getHashedPassword();
        HashService service = hashers.get(reference.getEncryption());
        if (service == null) {
            return null;
        }

        boolean match = service.validate(password, reference);
        if (!match) {
            return null;
        }

        return createSubject(info);
    }

    private Subject createSubject(UserInfo info) {
        Subject subject = new Subject();
        subject.getPrincipals().add(new UserPrincipal(info.getUsername()));
        // TODO What if there is no roles associated ?
        if (!info.getRoles().isEmpty()) {
            subject.getPrincipals().add(createGroup(info.getRoles()));
        }
        subject.setReadOnly();
        return subject;
    }

    private Group createGroup(Set<String> roles) {
        RoleGroup group = new RoleGroup();
        for (String role : roles) {
            group.addMember(new RolePrincipal(role));
        }
        return group;
    }

    private class ClassRelativeResource implements Resource {
        private final String name;

        public ClassRelativeResource(String name) {
            this.name = name;
        }

        @Override
        public InputStream openStream() throws RepositoryException {
            try {
                return getClass().getResource(name).openStream();
            } catch (IOException e) {
                throw new RepositoryException("Cannot push 'users.properties'", e);
            }
        }
    }
}
