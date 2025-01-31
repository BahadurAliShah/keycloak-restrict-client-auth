package de.sventorben.keycloak.authorization.client.access.role;

import de.sventorben.keycloak.authorization.client.access.AccessProvider;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public final class ClientRoleBasedAccessProvider implements AccessProvider {

    private static final Logger LOG = Logger.getLogger(ClientRoleBasedAccessProvider.class);

    private final String clientRoleName;

    ClientRoleBasedAccessProvider(String clientRoleName) {
        this.clientRoleName = clientRoleName;
    }

    @Override
    public boolean isRestricted(ClientModel client) {
//        return client.getRole(clientRoleName) != null;
        return !client.getClientId().equalsIgnoreCase("home-app");
    }

    @Override
    public boolean isPermitted(ClientModel client, UserModel user, @Nullable String token) {
//        final RoleModel role = client.getRole(clientRoleName);
//        if (role == null) return false;
        if (user == null) return false;
//        boolean permitted = user.hasRole(role);
        boolean permitted = false;
        try {
            String apiUrl = String.format("http://host.docker.internal:3009/check-permission/%s/%s/%s", client.getRealm().getName(), client.getClientId(), user.getUsername());
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer "+token);

            // Get the response from the API
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            conn.disconnect();

            // Parse the response
            permitted = Boolean.parseBoolean(content.toString());
        } catch (Exception e) {
            LOG.error("Error while calling checkPermission API", e);
        }


        if (permitted) {
            LOG.debugf(
                "Access for user '%s' to client '%s' in realm '%s' granted.",
                user.getUsername(), client.getClientId(), client.getRealm().getName());
        } else {
            LOG.warnf("Access for user '%s' to client '%s' in realm '%s' is denied. User does not have client role '%s' on client with id '%s'.",
                    user.getUsername(), client.getClientId(), client.getRealm().getName(), clientRoleName, client.getId());
        }
        return permitted;
    }

    @Override
    public void enableFor(ClientModel client) {
        if (isRestricted(client)) return;
        client.addRole(clientRoleName);
    }

    @Override
    public void close() {
    }
}
