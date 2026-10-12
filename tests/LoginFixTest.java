import java.lang.reflect.Proxy;
import java.sql.*;

public class LoginFixTest {
    static String sql;
    static String[] parameters = new String[3];

    static Object mock(Class<?> type,
                       java.lang.reflect.InvocationHandler handler) {
        return Proxy.newProxyInstance(
            LoginFixTest.class.getClassLoader(),
            new Class<?>[]{type}, handler);
    }

    static Connection connection() {
        ResultSet results = (ResultSet) mock(ResultSet.class,
            (proxy, method, args) -> {
                if (method.getName().equals("next")) {
                    return "alice".equals(parameters[1])
                        && LoginService.hashPassword("example-password")
                            .equals(parameters[2]);
                }
                return null;
            });

        PreparedStatement statement =
            (PreparedStatement) mock(PreparedStatement.class,
                (proxy, method, args) -> {
                    if (method.getName().equals("setString")) {
                        parameters[(Integer) args[0]] = (String) args[1];
                    }
                    if (method.getName().equals("executeQuery")) {
                        return results;
                    }
                    return null;
                });

        return (Connection) mock(Connection.class,
            (proxy, method, args) -> {
                if (method.getName().equals("prepareStatement")) {
                    sql = (String) args[0];
                    return statement;
                }
                return null;
            });
    }

    static void check(boolean condition, String description) {
        if (!condition) {
            throw new AssertionError("FAIL: " + description);
        }
        System.out.println("PASS: " + description);
    }

    public static void main(String[] args) throws Exception {
        Connection conn = connection();

        check(LoginService.login(conn, "alice", "example-password"),
              "Valid credentials follow the database result");

        check(!LoginService.login(conn, "alice", "wrong-password"),
              "Wrong password is rejected");

        String attack = "' OR '1'='1' -- ";
        check(!LoginService.login(conn, attack, "anything"),
              "Injection input receives a negative simulated result");

        check(sql.equals(
              "SELECT * FROM users WHERE username = ? AND password = ?"),
              "SQL template remains fixed");

        check(attack.equals(parameters[1]),
              "Injection input is bound separately as parameter 1");

        check(LoginService.hashPassword("anything").equals(parameters[2]),
              "Password hash is bound separately as parameter 2");

        check(!LoginService.login(conn, "admin", "Sup3rSecret!"),
              "Old administrator credentials do not bypass authentication");

        Connection unavailable = (Connection) mock(Connection.class,
            (proxy, method, values) -> {
                throw new SQLException("Simulated database outage");
            });

        boolean accessGranted = false;
        boolean outageReported = false;
        try {
            accessGranted = LoginService.login(
                unavailable, "admin", "Sup3rSecret!");
        } catch (SQLException expected) {
            outageReported = true;
        }

        check(outageReported && !accessGranted,
              "Database outage does not grant administrator access");
    }
}
