package au.org.massive.guacamole.auth;

import com.google.gson.Gson;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by simonyu on 5/03/15.
 */
public class CookiesAuthenticationProvider extends SimpleAuthenticationProvider {

    /**
     * Logger for this class.
     */
    private Logger logger = LoggerFactory.getLogger(CookiesAuthenticationProvider.class);

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {

        Map<String, GuacamoleConfiguration> configurations = new HashMap<String, GuacamoleConfiguration>();
        GuacamoleConfiguration configuration = new GuacamoleConfiguration();

        //get http servlet request from the Credentials object
        HttpServletRequest request = credentials.getRequest();
        Map<String,String> vncCredentials;
        Gson gson = new Gson();
        for (Cookie c : request.getCookies()) {
            if (c.getName().startsWith("vnc-credentials")) {
                //noinspection unchecked
                vncCredentials = gson.fromJson(c.getValue(), Map.class);

                configuration.setParameter("hostname", vncCredentials.get("hostname"));
                configuration.setParameter("port", vncCredentials.get("port"));
                configuration.setParameter("password", vncCredentials.get("password"));
                configuration.setProtocol(vncCredentials.get("protocol"));
                configurations.put(vncCredentials.get("name"), configuration);
            }
        }

        return configurations;
    }
}
