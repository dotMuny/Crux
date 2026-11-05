"""La base local y su migración mínima.

Crux no lleva Alembic: para un fichero SQLite por analista sería más maquinaria
que problema. Lo que sí lleva es lo único que no puede perder datos de nadie —
añadir columnas que el modelo ya declara— y eso tiene que estar probado, porque
el fallo que evita es silencioso: una base creada con una versión anterior
arranca bien y revienta al leer la primera fila.
"""

from __future__ import annotations

import sqlite3

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine

from crux.core.store import _anadir_columnas_nuevas, init_db


def columnas(ruta, tabla: str) -> set[str]:
    with sqlite3.connect(ruta) as conexion:
        return {f[1] for f in conexion.execute(f"PRAGMA table_info({tabla})")}


def test_crear_el_esquema_es_idempotente(tmp_path):
    base = tmp_path / "a.db"
    init_db(base)
    antes = columnas(base, "scans")
    init_db(base)
    assert columnas(base, "scans") == antes


def test_una_base_vieja_recibe_las_columnas_nuevas(tmp_path):
    """El caso real: la base del analista se creó antes de que existiera
    `scans.surface`, y hay escaneos dentro que no se pueden perder."""
    base = tmp_path / "vieja.db"
    init_db(base)

    # Se simula la versión anterior quitando la columna, con una fila dentro.
    with sqlite3.connect(base) as conexion:
        conexion.execute(
            "INSERT INTO projects (id, slug, name, description, created_at) "
            "VALUES (1, 'p', 'P', '', '2026-01-01 00:00:00')"
        )
        conexion.execute(
            "INSERT INTO scans (id, project_id, kind, profile, status, scope, "
            "tool_versions, coverage, surface, created_at) "
            "VALUES (7, 1, 'web', 'passive', 'done', '{}', '{}', '{}', '{}', "
            "'2026-01-01 00:00:00')"
        )
        conexion.execute("ALTER TABLE scans DROP COLUMN surface")
    assert "surface" not in columnas(base, "scans")

    init_db(base)

    assert "surface" in columnas(base, "scans")
    with sqlite3.connect(base) as conexion:
        fila = conexion.execute("SELECT id, surface FROM scans WHERE id = 7").fetchone()
    assert fila[0] == 7, "la fila que ya estaba tiene que seguir ahí"
    # Las columnas JSON llegan con su documento vacío, no con NULL: el código
    # que las lee espera un diccionario.
    assert fila[1] == "{}"


def test_no_se_toca_una_tabla_ajena(tmp_path):
    """La migración solo mira las tablas del modelo. Una tabla que no es
    nuestra en el mismo fichero se queda exactamente como está."""
    base = tmp_path / "mixta.db"
    init_db(base)
    with sqlite3.connect(base) as conexion:
        conexion.execute("CREATE TABLE notas (id INTEGER PRIMARY KEY, texto TEXT)")

    init_db(base)
    assert columnas(base, "notas") == {"id", "texto"}


def test_una_columna_obligatoria_sin_defecto_no_rompe_el_arranque(tmp_path):
    """SQLite no puede añadir una columna NOT NULL sin valor por defecto a una
    tabla con filas. Se deja estar en vez de reventar: un cambio así necesita
    decisión humana, no automatismo."""
    base = tmp_path / "dura.db"
    motor = create_engine(f"sqlite+pysqlite:///{base}")
    metadatos = MetaData()
    Table("cosas", metadatos, Column("id", Integer, primary_key=True))
    metadatos.create_all(motor)
    with sqlite3.connect(base) as conexion:
        conexion.execute("INSERT INTO cosas (id) VALUES (1)")

    # El modelo gana una columna obligatoria sin defecto.
    otros = MetaData()
    Table("cosas", otros,
          Column("id", Integer, primary_key=True),
          Column("obligatoria", String(10), nullable=False))

    import crux.core.store as store

    original = store.Base.metadata
    try:
        store.Base.metadata = otros
        _anadir_columnas_nuevas(motor)       # no debe lanzar
    finally:
        store.Base.metadata = original
    assert "obligatoria" not in columnas(base, "cosas")
