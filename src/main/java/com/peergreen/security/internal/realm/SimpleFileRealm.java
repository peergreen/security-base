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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.acl.Group;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.Subject;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Requires;
import org.apache.felix.ipojo.annotations.StaticServiceProperty;
import org.apache.felix.ipojo.annotations.Unbind;
import org.apache.felix.ipojo.annotations.Validate;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import com.peergreen.configuration.api.ConfigRepository;
import com.peergreen.configuration.api.Read;
import com.peergreen.configuration.api.RepositoryException;
import com.peergreen.configuration.api.Resource;
import com.peergreen.configuration.api.Version;
import com.peergreen.configuration.api.VersionedResource;
import com.peergreen.configuration.api.Write;
import com.peergreen.configuration.simple.FileConfiguration;
import com.peergreen.security.UsernamePasswordAuthenticateService;
import com.peergreen.security.encode.EncoderService;
import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashService;
import com.peergreen.security.internal.hash.util.References;
import com.peergreen.security.principal.RoleGroup;
import com.peergreen.security.principal.RolePrincipal;
import com.peergreen.security.principal.UserPrincipal;
import com.peergreen.security.realm.AccountFilter;
import com.peergreen.security.realm.AccountInfo;
import com.peergreen.security.realm.AccountStore;
import com.peergreen.security.realm.AccountStoreException;
import com.peergreen.security.realm.ModifiableAccountStore;

/**
 * User: guillaume
 * Date: 19/03/13
 * Time: 16:53
 */
@Component
@Provides(
        properties = @StaticServiceProperty(name = AccountStore.STORE_NAME, type = "java.lang.String", mandatory = true)
)
public class SimpleFileRealm implements UsernamePasswordAuthenticateService, ModifiableAccountStore {

    private Map<String, UserInfo> users = new HashMap<>();
    private Map<String, HashService> hashers = new HashMap<>();
    private ConfigRepository repository;
    private File baseRepository;

    private HashService defaultHasher;
    private EncoderService defaultEncoder;

    public SimpleFileRealm(BundleContext bundleContext,
                           @Requires(filter = "(hash.name=plain)") HashService hasher,
                           @Requires(filter = "(encoder.format=text)") EncoderService encoder) {
        this(bundleContext.getDataFile("repository"), hasher, encoder);
    }

    public SimpleFileRealm(File baseRepository, HashService hasher, EncoderService encoder) {
        this.baseRepository = baseRepository;
        this.defaultHasher = hasher;
        this.defaultEncoder = encoder;
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
                HashService service = hashers.get(encryption);
                if ((service == null) && "plain".equals(encryption)) {
                    service = defaultHasher;
                }
                return service;
            }
        });

        try (InputStream uis = uresource.openStream(); InputStream gis = gresource.openStream()) {
            Properties users = new Properties();
            users.load(uis);

            Properties groups = new Properties();
            groups.load(gis);

            Collection<UserInfo> userInfos = loader.load(users, groups);

            for (UserInfo info : userInfos) {
                this.users.put(info.getLogin(), info);
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
        subject.getPrincipals().add(new UserPrincipal(info.getLogin()));
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

    @Override
    public void createAccount(String id, String password)  throws AccountStoreException {
        UserInfo user = new UserInfo(id, defaultHasher.generate(password));
        users.put(id, user);
        persist();
    }

    @Override
    public boolean suppressAccount(String id) throws AccountStoreException {
        try {
            return users.remove(id) != null;
        } finally {
            persist();
        }
    }

    @Override
    public void activateAccount(String id) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void deactivateAccount(String id) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public AccountInfo getAccountInfo(String id) {
        return users.get(id);
    }

    @Override
    public void setPassword(String id, String password) throws AccountStoreException {
        Hash hash = defaultHasher.generate(password);
        UserInfo user = users.get(id);
        if (user != null) {
            user.setHashedPassword(hash);
            persist();
        } else {
            throw new AccountStoreException(format("Account '%s' unknown", id));
        }
    }

    @Override
    public void setLogin(String id, String newLogin) throws AccountStoreException {
        UserInfo user = users.remove(id);
        if (user != null) {
            user.setLogin(newLogin);
            users.put(newLogin, user);
            persist();
        } else {
            throw new AccountStoreException(format("Account '%s' unknown", id));
        }
    }

    @Override
    public void addRoles(String id, Collection<String> roles) throws AccountStoreException {
        UserInfo user = users.get(id);
        if (user != null) {
            for (String role : roles) {
                user.addRole(role);
            }
            persist();
        } else {
            throw new AccountStoreException(format("Account '%s' unknown", id));
        }
    }

    @Override
    public void removeRole(String id, Collection<String> roles) throws AccountStoreException {
        UserInfo user = users.get(id);
        if (user != null) {
            for (String role : roles) {
                user.removeRole(role);
            }
            persist();
        } else {
            throw new AccountStoreException(format("Account '%s' unknown", id));
        }
    }

    @Override
    public Set<AccountInfo> getAccounts(AccountFilter filter) {
        Set<AccountInfo> accounts = new HashSet<>();
        for (UserInfo userInfo : users.values()) {
            if (filter.accept(userInfo)) {
                accounts.add(userInfo);
            }
        }
        return accounts;
    }

    private void persist() throws AccountStoreException {

        Properties persisted = new Properties();
        Properties groups = new Properties();
        for (UserInfo userInfo : users.values()) {
            String login = userInfo.getLogin();
            persisted.setProperty(login, encode(userInfo.getHashedPassword()));
            for (String role : userInfo.getRoles()) {
                String value = groups.getProperty(role);
                if (value == null) {
                    value = login;
                } else {
                    value += "," + login;
                }
                groups.setProperty(role, value);
            }
        }

        try {
            Version current = repository.getProductionVersion();
            Write writer = repository.init(current);
            writer.pushResource("users.properties", new PropertiesResource(persisted));
            writer.pushResource("groups.properties", new PropertiesResource(groups));

            final String id = UUID.randomUUID().toString();
            Version updated = new Version() {
                @Override
                public String getName() {
                    return id;
                }
            };
            writer.tag(updated);
            repository.setProductionVersion(updated);
        } catch (RepositoryException e) {
            throw new AccountStoreException("Could not persist the change(s); modification will only be active on memory", e);
        }
    }

    private String encode(Hash hash) {
        // TODO encoder format should be variable
        return format("{%s+%s}%s", hash.getEncryption(), "text", defaultEncoder.encode(hash.getHashedValue()));
    }

    private class PropertiesResource implements Resource {

        private final Properties properties;

        public PropertiesResource(Properties properties) {
            this.properties = properties;
        }

        @Override
        public InputStream openStream() throws RepositoryException {

            StringBuilder sb = new StringBuilder();
            sb.append(format("# Generated by %s the %tc%n%n", getClass().getSimpleName(), new Date()));
            for (String name : properties.stringPropertyNames()) {
                String value = properties.getProperty(name);
                sb.append(format("%s %s%n", name, value));
            }
            return new ByteArrayInputStream(sb.toString().getBytes());
        }
    }
}
