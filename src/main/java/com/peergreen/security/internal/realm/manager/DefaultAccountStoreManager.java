package com.peergreen.security.internal.realm.manager;

import static java.lang.String.format;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Invalidate;
import org.apache.felix.ipojo.annotations.Unbind;
import org.apache.felix.ipojo.annotations.Validate;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceFactory;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;

import com.peergreen.security.realm.AccountStore;
import com.peergreen.security.realm.manager.AccountStoreManager;
import com.peergreen.security.realm.manager.ServiceHandle;

/**
 * User: guillaume
 * Date: 02/05/13
 * Time: 11:32
 */
@Component
@Instantiate
public class DefaultAccountStoreManager implements ServiceFactory<AccountStoreManager> {

    private final BundleContext bundleContext;
    private Map<String, ServiceReference<?>> references = new HashMap<>();
    private ServiceRegistration<?> registration;

    public DefaultAccountStoreManager(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    @Bind(specification = "com.peergreen.security.realm.AccountStore",
          filter = "(store.name=*)",
          aggregate = true)
    public void bindAccountStore(ServiceReference<?> reference) {
        String name = (String) reference.getProperty(AccountStore.STORE_NAME);
        references.put(name, reference);
    }

    @Unbind
    public void unbindAccountStore(ServiceReference<?> reference) {
        String name = (String) reference.getProperty(AccountStore.STORE_NAME);
        references.remove(name);
    }

    @Validate
    public void start() throws Exception {
        registration = bundleContext.registerService(AccountStoreManager.class.getName(), this, null);
    }

    @Invalidate
    public void stop() throws Exception {
        registration.unregister();
    }

    @Override
    public AccountStoreManager getService(Bundle bundle, ServiceRegistration<AccountStoreManager> registration) {
        return new ScopedAccountManager(bundle.getBundleContext());
    }

    @Override
    public void ungetService(Bundle bundle, ServiceRegistration<AccountStoreManager> registration, AccountStoreManager service) {
        ((ScopedAccountManager) service).close();
    }

    private class ScopedAccountManager implements AccountStoreManager {

        private final BundleContext bundleContext;
        private final List<ServiceHandle<?>> handles = new ArrayList<>();

        private ScopedAccountManager(BundleContext bundleContext) {
            this.bundleContext = bundleContext;
        }

        @Override
        public <T extends AccountStore> ServiceHandle<T> findAccountStore(String name, final Class<T> type) {
            final ServiceReference<?> reference = references.get(name);
            if (reference == null) {
                return null;
            }

            final Object o = bundleContext.getService(reference);
            if (!type.isInstance(o)) {
                throw new IllegalStateException(format("AccountStore '%s' is not a %s", name, type.getName()));
            }
            ServiceHandle<T> handle = new ServiceHandle<T>() {
                @Override
                public T get() {
                    return type.cast(o);
                }

                @Override
                public void release() {
                    bundleContext.ungetService(reference);
                    handles.remove(this);
                }
            };
            handles.add(handle);
            return handle;
        }

        @Override
        public List<String> listStoreNames() {
            return new ArrayList<>(references.keySet());
        }

        public void close() {
            // Force remaining handles to be released
            List<ServiceHandle<?>> clone = new ArrayList<>(handles);
            for (ServiceHandle<?> handle : clone) {
                handle.release();
            }
        }

    }
}
