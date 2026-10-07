package com.sonacomstar.planted;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Deliberately vulnerable. Do not use. */
public class UserServlet extends HttpServlet {
    // Planted: hard-coded credential (fake).
    private static final String DB_PASSWORD = "Sup3rS3cretPlantedPassw0rd!";
    private static final String API_KEY = "k8Jd93hFq02LsmZx81VbQe7TnPo4RwUy";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:planted", "sa", DB_PASSWORD);
             Statement s = c.createStatement()) {
            // Planted: SQL injection by string concatenation.
            ResultSet rs = s.executeQuery("SELECT id FROM users WHERE name = '" + name + "'");
            while (rs.next()) {
                // Planted: reflected XSS.
                resp.getWriter().println("<p>user " + rs.getString(1) + " for " + name + "</p>");
            }
        } catch (SQLException e) {
            resp.sendError(500, e.getMessage());
        }
    }
}
