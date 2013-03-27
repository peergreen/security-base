package com.peergreen.security.internal.hash.digest;

import com.peergreen.security.hash.Hash;

/**
 * User: guillaume
 * Date: 26/03/13
 * Time: 21:35
 */
public class DigestedHash implements Hash {

    private final String encryption;
    private final byte[] value;

    public DigestedHash(String encryption, byte[] value) {
        this.encryption = encryption;
        this.value = value;
    }

    @Override
    public byte[] getHashedValue() {
        return value;
    }

    @Override
    public String getEncryption() {
        return encryption;
    }
}
