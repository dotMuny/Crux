using System;
using System.Data.SqlClient;

namespace Corp {
    public class Facturas {
        // hardcoded-secret
        private const string ConnString =
            "Server=db.intra.corp;Database=billing;User Id=sa;Password=Verano2026!;";

        public void Buscar(string nombre) {
            // sql-injection
            var cmd = new SqlCommand(
                "SELECT * FROM clientes WHERE nombre = '" + nombre + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
