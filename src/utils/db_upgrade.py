"""Évolutions ADDITIVES du schéma d'xauth pour une base qui existe déjà (`create_all` ne modifie jamais une table existante).

Fichier AUTONOME (aucun import relatif) : les tests le chargent tel quel. Uniquement des colonnes nullables et des index : une base jamais touchée n'a rien à faire,
une base ancienne gagne ce qui lui manque, rien n'est jamais supprimé ni réécrit.
"""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

# (table, colonne, type SQL, index unique éventuel)
ADDED_COLUMNS: list[tuple[str, str, str, str | None]] = [
    ("xauth_users", "username", "VARCHAR(64)", "ux_xauth_users_username"),
]


def add_missing_columns(conn: Connection) -> list[str]:
    """Ajoute les colonnes manquantes et leur index unique ; rend ce qui a été fait (pour le journal)."""
    done: list[str] = []
    insp = inspect(conn)
    for table, column, sql_type, unique_index in ADDED_COLUMNS:
        if not insp.has_table(table):
            continue  # table absente : `create_all` la crée complète
        if column not in {c["name"] for c in insp.get_columns(table)}:
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {sql_type}'))
            done.append(f"{table}.{column}")
        if unique_index and unique_index not in {i["name"] for i in insp.get_indexes(table)}:
            # Les NULL ne se heurtent pas (SQLite comme PostgreSQL) : seuls les noms posés sont uniques.
            conn.execute(text(f'CREATE UNIQUE INDEX {unique_index} ON {table} ({column})'))
            done.append(f"index {unique_index}")
    return done
