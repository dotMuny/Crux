<?php
// Portal de clientes. Código con fallos plantados para pruebas.

// hardcoded-secret
$db_password = "Correo.2026";

// sql-injection
$nombre = $_GET['nombre'];
$resultado = mysqli_query($conexion, "SELECT * FROM clientes WHERE nombre = '$nombre'");

// xss: se imprime entrada sin escapar
echo "<h1>Hola " . $_GET['usuario'] . "</h1>";

// command-injection
system("exportar --formato " . $_GET['formato']);

// file-inclusion
include($_GET['pagina'] . ".php");
