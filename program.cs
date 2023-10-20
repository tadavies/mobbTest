using System;
using Microsoft.Data.SqlClient;

public class Program
{
    
    public static void Main(string[] args)
    {
        sqlHelper sql = new sqlHelper();
        sql.init();
        sql.vuln_string_concat(args[0]);
        sql.vuln_string_concat_multiple(args[0]);
        sql.vuln_string_interpolation(args[0]);
        sql.vuln_insert_multiple_vars(args[0], args[1], args[2]);
        sql.vuln_where_equal_num(args[0]);
    }
}
public class sqlHelper
{
    private SqlConnectionStringBuilder _builder;
    public void vuln_string_concat(string login)
    {
        using (SqlConnection connection = new SqlConnection(this._builder.ConnectionString))
        {
            String sql = "SELECT * FROM User WHERE login = '" + login + "'";
            using (SqlCommand command = new SqlCommand(sql, connection))
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("{0} {1}", reader.GetString(0), reader.GetString(1));
                    }
                }
            }                    
        }
    }
    public void vuln_string_concat_multiple(string login)
    {
        using (SqlConnection connection = new SqlConnection(this._builder.ConnectionString))
        {
            string start = "SELECT * FROM";
            string query = start + "User  WHERE login = '" + login + "'";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("{0} {1}", reader.GetString(0), reader.GetString(1));
                    }
                }
            }                    
        }
    }
    public void vuln_string_interpolation(string login)
    {
        using (SqlConnection connection = new SqlConnection(this._builder.ConnectionString))
        {
            string start = "SELECT * FROM";
            string query = $"{start} User  WHERE login = '{login}'";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("{0} {1}", reader.GetString(0), reader.GetString(1));
                    }
                }
            }                    
        }
    }
    public void vuln_insert_multiple_vars(string productCode, string email, string comment)
    {
        using (SqlConnection connection = new SqlConnection(this._builder.ConnectionString))
        {
            string query = "insert into Comments(productCode, email, comment) values ('" + productCode + "','" + email + "','" + comment + "');";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("{0} {1}", reader.GetString(0), reader.GetString(1));
                    }
                }
            }                    
        }
    }
    public void vuln_where_equal_num(string num)
    {
        using (SqlConnection connection = new SqlConnection(this._builder.ConnectionString))
        {
            string query = "select email from CustomerLogin where customerNumber = " + num;
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine("{0} {1}", reader.GetString(0), reader.GetString(1));
                    }
                }
            }                    
        }
    }
    public void init()
    {
        this._builder = new SqlConnectionStringBuilder();
        this._builder.DataSource = "<your_server>.database.windows.net"; 
        this._builder.UserID = "<your_username>";            
        this._builder.Password = "<your_password>";     
        this._builder.InitialCatalog = "<your_database>";
    }
}
