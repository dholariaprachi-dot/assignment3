import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class LoginService {

    public static boolean login(Connection conn, String username,
                                String password) throws SQLException {
        return authenticate(conn, username, password);
    }

    public static String hashPassword(String plainPassword) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(plainPassword.getBytes());
            StringBuilder sb = new StringBuilder();

            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String buildLoginQuery(String username, String password) {
        return "SELECT * FROM users WHERE username = ? AND password = ?";
    }

    public static boolean authenticate(Connection conn, String username,
                                       String password) throws SQLException {
        String hashed = hashPassword(password);
        String sql = buildLoginQuery(username, password);

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, hashed);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    public static void main(String[] args) {
        String username = args[0];
        String password = args[1];

        System.out.println("SQL template: "
                + buildLoginQuery(username, password));
    }
}