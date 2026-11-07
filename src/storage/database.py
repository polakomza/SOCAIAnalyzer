import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / 'data' / 'soc_analyzer.db'


def connect(db_path=DEFAULT_DB):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute('PRAGMA foreign_keys = ON')
    return connection


def init_database(db_path=DEFAULT_DB):
    with connect(db_path) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                source_name TEXT NOT NULL,
                sheet_name TEXT NOT NULL,
                total_events INTEGER NOT NULL,
                valid_events INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                finding_json TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                incident_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                incident_json TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                UNIQUE (analysis_id, incident_id)
            );
            CREATE TABLE IF NOT EXISTS risk_evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                incident_id TEXT NOT NULL,
                evaluation_json TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                UNIQUE (analysis_id, incident_id)
            );
            CREATE TABLE IF NOT EXISTS risk_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                incident_id TEXT NOT NULL,
                review_json TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                UNIQUE (analysis_id, incident_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_analysis ON incidents(analysis_id);
        ''')
        # Migración no destructiva: las versiones antiguas conservan su ID.
        columns = {row[1] for row in conn.execute('PRAGMA table_info(analyses)')}
        if 'base_analysis_key' not in columns:
            conn.execute('ALTER TABLE analyses ADD COLUMN base_analysis_key TEXT')
        if 'result_hash' not in columns:
            conn.execute('ALTER TABLE analyses ADD COLUMN result_hash TEXT')
        conn.execute('''
            UPDATE analyses SET base_analysis_key = analysis_key
            WHERE base_analysis_key IS NULL
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_analyses_base
            ON analyses(base_analysis_key)
        ''')


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _result_hash(findings, incidents, total_events, valid_events):
    # Ignora el orden de los elementos, no su contenido ni repeticiones.
    payload = {
        'findings': sorted(_json(item) for item in findings),
        'incidents': sorted(_json(item) for item in incidents),
        'total_events': int(total_events),
        'valid_events': int(valid_events),
    }
    return hashlib.sha256(_json(payload).encode('utf-8')).hexdigest()


def _hash_saved(conn, analysis_id, total_events, valid_events):
    findings = [json.loads(row[0]) for row in conn.execute(
        'SELECT finding_json FROM findings WHERE analysis_id = ?', (analysis_id,)
    )]
    incidents = [json.loads(row[0]) for row in conn.execute(
        'SELECT incident_json FROM incidents WHERE analysis_id = ?', (analysis_id,)
    )]
    return _result_hash(findings, incidents, total_events, valid_events)


def save_analysis(
    analysis_key, source_name, sheet_name, total_events, valid_events,
    findings, incidents, db_path=DEFAULT_DB
):
    """Crea una versión solo cuando cambian los resultados; devuelve (id, creado)."""
    init_database(db_path)
    fingerprint = _result_hash(findings, incidents, total_events, valid_events)

    with connect(db_path) as conn:
        rows = conn.execute('''
            SELECT id, result_hash, total_events, valid_events
            FROM analyses WHERE base_analysis_key = ? ORDER BY id DESC
        ''', (analysis_key,)).fetchall()

        for row in rows:
            saved_hash = row[1] or _hash_saved(conn, row[0], row[2], row[3])
            if not row[1]:
                conn.execute(
                    'UPDATE analyses SET result_hash = ? WHERE id = ?',
                    (saved_hash, row[0]),
                )
            if saved_hash == fingerprint:
                return row[0], False

        # La columna analysis_key original sigue siendo UNIQUE: una clave
        # diferente por versión evita reconstruir la tabla existente.
        version_key = 'v2:' + hashlib.sha256(
            (analysis_key + ':' + fingerprint).encode('utf-8')
        ).hexdigest()
        cursor = conn.execute('''
            INSERT INTO analyses (
                analysis_key, base_analysis_key, result_hash, created_at,
                source_name, sheet_name, total_events, valid_events
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            version_key, analysis_key, fingerprint,
            datetime.now(timezone.utc).isoformat(),
            source_name, sheet_name, total_events, valid_events,
        ))
        analysis_id = cursor.lastrowid

        for finding in findings:
            conn.execute(
                'INSERT INTO findings (analysis_id, finding_json) VALUES (?, ?)',
                (analysis_id, json.dumps(finding, ensure_ascii=False, default=str)),
            )
        for incident in incidents:
            conn.execute('''
                INSERT INTO incidents (analysis_id, incident_id, severity, incident_json)
                VALUES (?, ?, ?, ?)
            ''', (
                analysis_id, str(incident['incident_id']), incident['severity'],
                json.dumps(incident, ensure_ascii=False, default=str),
            ))
        return analysis_id, True


def save_risk_results(
    analysis_key, risk_evaluations, risk_reviews, db_path=DEFAULT_DB,
    analysis_id=None,
):
    """Guarda resultados de riesgo en una versión concreta del análisis."""
    init_database(db_path)
    with connect(db_path) as conn:
        if analysis_id is None:
            candidates = conn.execute(
                'SELECT id FROM analyses WHERE base_analysis_key = ?',
                (analysis_key,),
            ).fetchall()
            if len(candidates) != 1:
                raise ValueError('Indicá analysis_id: existen varias versiones del análisis.')
            analysis_id = candidates[0][0]
        else:
            row = conn.execute(
                'SELECT id FROM analyses WHERE id = ? AND base_analysis_key = ?',
                (analysis_id, analysis_key),
            ).fetchone()
            if row is None:
                raise ValueError('La versión del análisis no existe.')

        allowed_ids = {
            row[0] for row in conn.execute(
                'SELECT incident_id FROM incidents WHERE analysis_id = ?',
                (analysis_id,),
            )
        }
        for incident_id, evaluation in risk_evaluations.items():
            incident_id = str(incident_id)
            if incident_id not in allowed_ids:
                continue
            serialized = json.dumps(evaluation, ensure_ascii=False, default=str)
            previous = conn.execute('''
                SELECT evaluation_json FROM risk_evaluations
                WHERE analysis_id = ? AND incident_id = ?
            ''', (analysis_id, incident_id)).fetchone()
            if previous and previous[0] != serialized:
                # Una nueva evaluación invalida una revisión de la anterior.
                conn.execute('''
                    DELETE FROM risk_reviews WHERE analysis_id = ? AND incident_id = ?
                ''', (analysis_id, incident_id))
            conn.execute('''
                INSERT INTO risk_evaluations (analysis_id, incident_id, evaluation_json)
                VALUES (?, ?, ?)
                ON CONFLICT(analysis_id, incident_id)
                DO UPDATE SET evaluation_json = excluded.evaluation_json
            ''', (analysis_id, incident_id, serialized))

        # La vista ya filtra revisiones vigentes mediante is_review_current.
        # Solo se permite guardar una revisión si su evaluación está incluida.
        for incident_id, review in risk_reviews.items():
            incident_id = str(incident_id)
            if incident_id not in allowed_ids or incident_id not in risk_evaluations:
                continue
            conn.execute('''
                INSERT INTO risk_reviews (analysis_id, incident_id, review_json)
                VALUES (?, ?, ?)
                ON CONFLICT(analysis_id, incident_id)
                DO UPDATE SET review_json = excluded.review_json
            ''', (
                analysis_id, incident_id,
                json.dumps(review, ensure_ascii=False, default=str),
            ))


def list_analyses(db_path=DEFAULT_DB):
    init_database(db_path)
    with connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('''
            SELECT a.id, a.created_at, a.source_name, a.sheet_name,
                   a.total_events, a.valid_events,
                   COUNT(DISTINCT f.id) AS findings_count,
                   COUNT(DISTINCT i.id) AS incidents_count
            FROM analyses a
            LEFT JOIN findings f ON f.analysis_id = a.id
            LEFT JOIN incidents i ON i.analysis_id = a.id
            GROUP BY a.id ORDER BY a.id DESC
        ''').fetchall()
        return [dict(row) for row in rows]


def load_analysis(analysis_id, db_path=DEFAULT_DB):
    init_database(db_path)
    with connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        analysis = conn.execute(
            'SELECT * FROM analyses WHERE id = ?', (analysis_id,)
        ).fetchone()
        if analysis is None:
            return None
        findings = conn.execute('''
            SELECT finding_json FROM findings WHERE analysis_id = ? ORDER BY id
        ''', (analysis_id,)).fetchall()
        incidents = conn.execute('''
            SELECT incident_json FROM incidents WHERE analysis_id = ? ORDER BY id
        ''', (analysis_id,)).fetchall()
        return {
            'analysis': dict(analysis),
            'findings': [json.loads(row['finding_json']) for row in findings],
            'incidents': [json.loads(row['incident_json']) for row in incidents],
        }


def load_risk_results(analysis_id, db_path=DEFAULT_DB):
    init_database(db_path)
    with connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        evaluations = conn.execute('''
            SELECT incident_id, evaluation_json FROM risk_evaluations
            WHERE analysis_id = ?
        ''', (analysis_id,)).fetchall()
        reviews = conn.execute('''
            SELECT incident_id, review_json FROM risk_reviews
            WHERE analysis_id = ?
        ''', (analysis_id,)).fetchall()
        return {
            'risk_evaluations': {
                row['incident_id']: json.loads(row['evaluation_json'])
                for row in evaluations
            },
            'risk_reviews': {
                row['incident_id']: json.loads(row['review_json'])
                for row in reviews
            },
        }
