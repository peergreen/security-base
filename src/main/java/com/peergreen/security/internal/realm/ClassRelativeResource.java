package com.peergreen.security.internal.realm;

import java.io.IOException;
import java.io.InputStream;

import com.peergreen.configuration.api.RepositoryException;
import com.peergreen.configuration.api.Resource;

/**
 * User: guillaume
 * Date: 16/04/13
 * Time: 18:12
 */
public class ClassRelativeResource implements Resource {
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
