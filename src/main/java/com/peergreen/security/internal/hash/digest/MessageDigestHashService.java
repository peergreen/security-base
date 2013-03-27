package com.peergreen.security.internal.hash.digest;

import static java.lang.String.format;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Property;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.StaticServiceProperty;
import org.apache.felix.ipojo.annotations.Unbind;
import org.osgi.framework.ServiceReference;

import com.peergreen.security.encode.EncoderService;
import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashException;
import com.peergreen.security.hash.HashService;
import com.peergreen.security.internal.hash.util.References;

/**
 * @see <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest">Accepted algorithm names</a>
 */
@Component
@Provides(
        properties = @StaticServiceProperty(
                name = HashService.HASH_NAME_PROPERTY,
                value = "md5",
                type = "java.lang.String"
        )
)
public class MessageDigestHashService implements HashService {

    private final MessageDigest messageDigest;
    private Map<String, EncoderService> encoders = new HashMap<>();

    /**
     * Default encoder service (base64).
     */
    private EncoderService defaultEncoder;


    public MessageDigestHashService() throws NoSuchAlgorithmException {
        this("MD5");
    }

    public MessageDigestHashService(@Property(name = "algorithm") String algorithm) throws NoSuchAlgorithmException {
        this(MessageDigest.getInstance(algorithm));
    }

    public MessageDigestHashService(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }


    @Bind(aggregate = true)
    public void bindEncoder(EncoderService encoder, ServiceReference<EncoderService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, EncoderService.ENCODER_FORMAT);
        for (String name : names) {
            encoders.put(name, encoder);
        }
    }

    @Unbind
    public void unbindEncoder(ServiceReference<EncoderService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, EncoderService.ENCODER_FORMAT);
        for (String name : names) {
            encoders.remove(name);
        }
    }

    @Bind(filter = "(encoder.format=base64)")
    public void bindDefaultEncoder(EncoderService defaultEncoder) {
        this.defaultEncoder = defaultEncoder;
    }


    private EncoderService findEncoder(String format) {
        EncoderService encoder = encoders.get(format);
        if (encoder == null) {
            throw new IllegalArgumentException(format("No registered EncoderService for format '%s'",
                    format
            ));
        }
        return encoder;
    }

    @Override
    public synchronized Hash generate(String clear) {
        try {
            return new DigestedHash(messageDigest.getAlgorithm(),
                                    messageDigest.digest(clear.getBytes()));
        } finally {
            messageDigest.reset();
        }
    }

    @Override
    public synchronized Hash generate(String clear, byte[] salt) {
        try {
            return new DigestedHash(messageDigest.getAlgorithm(),
                    messageDigest.digest(clear.getBytes()));
        } finally {
            messageDigest.reset();
        }
    }

    @Override
    public Hash build(String encoder, String encoded) throws HashException {
        EncoderService encoderService;
        if (encoder != null) {
            encoderService = findEncoder(encoder);
        } else {
            encoderService = defaultEncoder;
        }
        return new DigestedHash(messageDigest.getAlgorithm(),
                                encoderService.decode(encoded));
    }

    @Override
    public boolean validate(String clear, Hash hash) {
        if (!(hash instanceof DigestedHash)) {
            throw new IllegalArgumentException(format(
                    "Hash parameter (type:%s) has not been provided by this (%s) HashService",
                    hash.getClass().getName(),
                    this.getClass().getName()
            ));
        }
        Hash test = generate(clear);
        return Arrays.equals(hash.getHashedValue(), test.getHashedValue());
    }
}
