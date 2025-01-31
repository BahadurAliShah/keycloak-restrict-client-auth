package de.sventorben.keycloak.authorization.client.access;

import org.checkerframework.checker.nullness.qual.Nullable;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

public interface AccessProvider extends Provider {
    boolean isRestricted(ClientModel client);

    boolean isPermitted(ClientModel client, UserModel user, @Nullable String token);

    void enableFor(ClientModel client);
}
