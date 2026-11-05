"""Acceso a la base local SQLite."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from . import paths
from .models import Base

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_connection, _record) -> None:
    """Pragmas que importan: claves ajenas activas (SQLite las ignora por
    defecto, y nuestro esquema depende del borrado en cascada) y WAL para que la
    UI pueda leer mientras un escaneo escribe."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def get_engine(db: Path | str | None = None, *, echo: bool = False) -> Engine:
    global _engine, _Session
    if _engine is not None and db is None:
        return _engine
    if db is None:
        paths.ensure_dirs()
        db = paths.db_path()
    url = db if str(db).startswith("sqlite") else f"sqlite+pysqlite:///{db}"
    engine = create_engine(url, echo=echo, future=True)
    event.listen(engine, "connect", _configure_sqlite)
    if db is None or str(db) == str(paths.db_path()):
        _engine = engine
        _Session = sessionmaker(bind=engine, expire_on_commit=False)
    return engine


def init_db(db: Path | str | None = None) -> Engine:
    """Crea el esquema si no existe y añade lo que falte. Idempotente."""
    engine = get_engine(db)
    Base.metadata.create_all(engine)
    _anadir_columnas_nuevas(engine)
    return engine


def _anadir_columnas_nuevas(engine: Engine) -> None:
    """Añade a las tablas existentes las columnas que el modelo ya declara.

    `create_all` crea tablas que no están, pero no toca las que sí: una base
    creada con una versión anterior se queda sin las columnas nuevas y falla al
    leerlas. Esto es una migración deliberadamente mínima —solo añadir, nunca
    quitar ni cambiar tipos— porque es el único cambio de esquema que no puede
    perder datos de nadie. Un cambio que no quepa aquí necesita decisión
    humana, no automatismo.
    """
    inspector = inspect(engine)
    existentes = set(inspector.get_table_names())
    with engine.begin() as conexion:
        for tabla in Base.metadata.sorted_tables:
            if tabla.name not in existentes:
                continue
            tiene = {c["name"] for c in inspector.get_columns(tabla.name)}
            for columna in tabla.columns:
                if columna.name in tiene:
                    continue
                if not columna.nullable and columna.default is None:
                    # Una columna obligatoria sin valor por defecto no se puede
                    # añadir a filas que ya existen. Se deja estar y se dice,
                    # en vez de romper el arranque.
                    continue
                tipo = columna.type.compile(engine.dialect)
                defecto = _defecto_sql(columna)
                conexion.execute(text(
                    f"ALTER TABLE {tabla.name} ADD COLUMN {columna.name} {tipo}"
                    + (f" DEFAULT {defecto}" if defecto is not None else "")
                ))


def _defecto_sql(columna) -> str | None:
    """El valor por defecto de la columna, escrito como literal de SQLite."""
    bruto = getattr(columna.default, "arg", None)
    if bruto is None:
        return None
    if callable(bruto):
        # Los por defecto de JSON son `dict` y `list`: su valor inicial es un
        # documento vacío, no una llamada que SQLite pueda hacer. SQLAlchemy
        # envuelve los invocables de cero argumentos en uno que recibe el
        # contexto de ejecución, así que hay que probar las dos formas: con la
        # primera sola, una columna JSON se quedaba sin DEFAULT y las filas que
        # ya existían recibían NULL donde el código espera un diccionario.
        for argumentos in ((), (None,)):
            try:
                bruto = bruto(*argumentos)
                break
            except TypeError:
                continue
        else:
            return None
    if isinstance(bruto, (dict, list)):
        import json

        return "'" + json.dumps(bruto) + "'"
    if isinstance(bruto, bool):
        return "1" if bruto else "0"
    if isinstance(bruto, (int, float)):
        return str(bruto)
    if isinstance(bruto, str):
        return "'" + bruto.replace("'", "''") + "'"
    return None


@contextmanager
def session_scope(db: Path | str | None = None) -> Iterator[Session]:
    """Sesión transaccional: commit al salir bien, rollback si algo falla."""
    global _Session
    engine = get_engine(db)
    factory = _Session if (db is None and _Session is not None) else sessionmaker(
        bind=engine, expire_on_commit=False
    )
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
