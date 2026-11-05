package corp;

import java.sql.*;
import java.io.*;

public class Facturas {
    // hardcoded-secret
    private static final String DB_PASS = "Primavera2026";

    public ResultSet buscar(Connection con, String nombre) throws SQLException {
        // sql-injection: concatenación en la consulta
        Statement st = con.createStatement();
        return st.executeQuery("SELECT * FROM clientes WHERE nombre = '" + nombre + "'");
    }

    public Object cargar(byte[] datos) throws Exception {
        // deserialization: deserializar datos no confiables
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(datos));
        return ois.readObject();
    }

    public void ejecutar(String formato) throws IOException {
        // command-injection
        Runtime.getRuntime().exec("exportar --formato " + formato);
    }
}
