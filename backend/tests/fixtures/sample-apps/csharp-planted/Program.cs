// Deliberately vulnerable. Do not use.
using System.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Planted: hard-coded connection string (fake).
const string ConnectionString = "Server=db.internal;Database=app;User Id=sa;Password=Sup3rS3cretPlantedPassw0rd!;";

app.MapGet("/user", (string name) =>
{
    using var connection = new SqlConnection(ConnectionString);
    connection.Open();
    // Planted: SQL injection by string concatenation.
    using var command = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", connection);
    using var reader = command.ExecuteReader();
    return reader.Read() ? Results.Ok(reader[0]?.ToString()) : Results.NotFound();
});

app.Run();
