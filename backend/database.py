import sqlite3
from datetime import datetime
from pathlib import Path

# Ruta de la base de datos en la raíz del proyecto
DB_PATH = Path(__file__).resolve().parent.parent / "pysentinel.db"


def init_db():
    """Crea la tabla de alertas si aún no existe."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tipo TEXT NOT NULL,
            severidad TEXT NOT NULL,
            ip_origen TEXT NOT NULL,
            detalle TEXT NOT NULL,
            archivo_pcap TEXT
        )
    """)
    conn.commit()
    conn.close()


def registrar_alerta(tipo: str, severidad: str, ip_origen: str, detalle: str, archivo_pcap: str = None) -> dict:
    """Guarda una nueva alerta de seguridad y devuelve el registro creado."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO alertas (timestamp, tipo, severidad, ip_origen, detalle, archivo_pcap)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, tipo, severidad, ip_origen, detalle, archivo_pcap),
    )
    alerta_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": alerta_id,
        "timestamp": timestamp,
        "tipo": tipo,
        "severidad": severidad,
        "ip_origen": ip_origen,
        "detalle": detalle,
        "archivo_pcap": archivo_pcap,
    }


def obtener_alertas(limite: int = 50) -> list[dict]:
    """Devuelve las últimas alertas registradas ordenadas de más reciente a más antigua."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alertas ORDER BY id DESC LIMIT ?", (limite,))
    filas = [dict(fila) for fila in cursor.fetchall()]
    conn.close()
    return filas