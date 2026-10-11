// fp-deser-java.java: Java PreparedStatement (parameterized) — SAFE
import java.sql.*;

public class SafeQuery {
    public static ResultSet getUser(Connection conn, String userId) throws SQLException {
        // SAFE: parameterized PreparedStatement
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        return stmt.executeQuery();
    }
}
