import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from email.utils import parseaddr
from urllib.request import Request, urlopen

import psycopg
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


logging.basicConfig(level=logging.INFO)
app = FastAPI(title="SiPP Authorization API", version="2.3.0")
CODE_MINUTES = 10
ACTION_MINUTES = 7 * 24 * 60
AUTH_CODE_SECRET_LOCAL = "configure-AUTH_CODE_SECRET-en-Render"
AUTH_API_KEY = os.getenv("AUTH_API_KEY", "").strip()


class AccessRequest(BaseModel):
    installation_id: str = Field(min_length=1, max_length=100)
    device_name: str = Field(default="Desconocido", max_length=255)
    windows_user: str = Field(default="Desconocido", max_length=255)
    operating_system: str = Field(default="Desconocido", max_length=255)
    ip_local: str = Field(default="Desconocida", max_length=64)
    system_machine: str = Field(default="Desconocida", max_length=100)
    system_release: str = Field(default="Desconocido", max_length=100)
    processor: str = Field(default="Desconocido", max_length=255)
    python_version: str = Field(default="Desconocida", max_length=40)
    app_version: str = Field(default="Desconocida", max_length=40)
    force_new: bool = False


class VerifyCode(BaseModel):
    installation_id: str = Field(min_length=1, max_length=100)
    code: str = Field(min_length=6, max_length=8)


class TermsAcceptance(BaseModel):
    installation_id: str = Field(min_length=1, max_length=100)
    device_name: str = Field(default="Desconocido", max_length=255)
    windows_user: str = Field(default="Desconocido", max_length=255)
    operating_system: str = Field(default="Desconocido", max_length=255)
    ip_local: str = Field(default="Desconocida", max_length=64)
    system_machine: str = Field(default="Desconocida", max_length=100)
    system_release: str = Field(default="Desconocido", max_length=100)
    processor: str = Field(default="Desconocido", max_length=255)
    python_version: str = Field(default="Desconocida", max_length=40)
    app_version: str = Field(default="Desconocida", max_length=40)
    terms_version: str = Field(min_length=1, max_length=40)
    terms_text: str = Field(min_length=1, max_length=30000)


def conectar():
    url = os.getenv("DATABASE_URL")
    if url:
        return psycopg.connect(url)
    import config_seguridad
    credenciales = config_seguridad.cargar_credenciales()
    if not credenciales:
        raise RuntimeError("Falta configurar DATABASE_URL o las credenciales locales de PostgreSQL.")
    return psycopg.connect(
        host=config_seguridad.DB_HOST,
        port=config_seguridad.DB_PORT,
        dbname=config_seguridad.DB_NAME,
        user=credenciales["usuario"],
        password=credenciales["contraseña"],
    )


def codigo_hash(request_id, code):
    secret = os.getenv("AUTH_CODE_SECRET", AUTH_CODE_SECRET_LOCAL)
    mensaje = f"{request_id}:{code}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), mensaje, hashlib.sha256).hexdigest()


def token_hash(token):
    secret = os.getenv("ADMIN_ACTION_SECRET", AUTH_CODE_SECRET_LOCAL)
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def enlace_accion(request_id, token, accion):
    base = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not base:
        raise RuntimeError("Configure PUBLIC_BASE_URL.")
    return f"{base}/admin/access-requests/{request_id}/{accion}?token={quote(token)}"


def enviar_mensaje(asunto, texto, html_cuerpo):
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    remitente = os.getenv("MAIL_FROM", "").strip()
    destinatario = os.getenv("MAIL_TO", "").strip()
    if not api_key or not remitente or not destinatario:
        raise RuntimeError("Configure BREVO_API_KEY, MAIL_FROM y MAIL_TO.")
    nombre_remitente, correo_remitente = parseaddr(remitente)
    if not correo_remitente:
        raise RuntimeError("MAIL_FROM debe contener una direccion de correo valida.")
    cuerpo = json.dumps(
        {
            "sender": {"name": nombre_remitente or "SiPP", "email": correo_remitente},
            "to": [{"email": destinatario}],
            "subject": asunto,
            "textContent": texto,
            "htmlContent": html_cuerpo,
        }
    ).encode("utf-8")
    solicitud = Request(
        "https://api.brevo.com/v3/smtp/email",
        data=cuerpo,
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(solicitud, timeout=20) as respuesta:
            if respuesta.status not in (200, 201):
                raise RuntimeError(f"Brevo devolvio HTTP {respuesta.status}.")
    except HTTPError as exc:
        try:
            detalle = json.loads(exc.read().decode("utf-8")).get("message", "")
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            detalle = ""
        raise RuntimeError(f"Brevo devolvio HTTP {exc.code}: {detalle}") from exc
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError(f"No se pudo contactar la API de Brevo: {exc}") from exc


def fila_a_respuesta(fila):
    return {
        "request_id": str(fila[0]),
        "status": fila[1],
        "expires_at": fila[2].isoformat() if fila[2] else None,
        "message": "Solicitud enviada" if fila[1] == "PENDIENTE" else f"Acceso {fila[1].lower()}",
    }


def enviar_correo(datos, request_id, code, expires_at, token):
    aprobacion = enlace_accion(request_id, token, "aprobar")
    rechazo = enlace_accion(request_id, token, "rechazar")
    bloqueo = enlace_accion(request_id, token, "bloquear")
    desbloqueo = enlace_accion(request_id, token, "desbloquear")
    detalles = (
        f"Equipo: {datos.device_name}\nUsuario: {datos.windows_user}\n"
        f"Sistema: {datos.operating_system}\nIdentificador: {datos.installation_id}\n"
        f"Codigo: {code}\nCaduca: {expires_at.isoformat()}"
    )
    html_cuerpo = f"""
    <h2>Solicitud de acceso a SiPP</h2>
    <p>Una computadora solicita permiso para usar SiPP.</p>
    <p><strong>Equipo:</strong> {html.escape(datos.device_name)}<br>
    <strong>Usuario:</strong> {html.escape(datos.windows_user)}<br>
    <strong>Sistema:</strong> {html.escape(datos.operating_system)}<br>
    <strong>Identificador:</strong> {html.escape(datos.installation_id)}</p>
    <p>Codigo para el usuario: <strong>{html.escape(code)}</strong></p>
    <p>Acciones administrativas:</p>
    <p><a href="{html.escape(aprobacion)}">APROBAR</a> | <a href="{html.escape(rechazo)}">RECHAZAR</a></p>
    <p><a href="{html.escape(bloqueo)}">BLOQUEAR EQUIPO</a> | <a href="{html.escape(desbloqueo)}">DESBLOQUEAR EQUIPO</a></p>
    <p>Los enlaces caducan en {ACTION_MINUTES // 1440} dias.</p>
    """
    enviar_mensaje(f"SiPP: solicitud de acceso ({datos.device_name})", detalles, html_cuerpo)
    return token


def enviar_correo_aceptacion(datos):
    detalles_equipo = f"""
    <ul>
      <li>Equipo: {html.escape(datos.device_name)}</li>
      <li>Usuario: {html.escape(datos.windows_user)}</li>
      <li>Sistema: {html.escape(datos.operating_system)}</li>
      <li>IP local: {html.escape(datos.ip_local)}</li>
      <li>Arquitectura: {html.escape(datos.system_machine)}</li>
      <li>Version del sistema: {html.escape(datos.system_release)}</li>
      <li>Procesador: {html.escape(datos.processor)}</li>
      <li>Python: {html.escape(datos.python_version)}</li>
      <li>Version de SiPP: {html.escape(datos.app_version)}</li>
      <li>Identificador: {html.escape(datos.installation_id)}</li>
    </ul>
    """
    cuerpo = f"Aceptacion de condiciones de SiPP.\nEquipo: {datos.device_name}\nIdentificador: {datos.installation_id}"
    html_cuerpo = f"<h2>Aceptacion de condiciones de SiPP</h2><h3>Equipo que accedio</h3>{detalles_equipo}<pre>{html.escape(datos.terms_text)}</pre>"
    enviar_mensaje(f"SiPP: condiciones aceptadas ({datos.windows_user})", cuerpo, html_cuerpo)


@app.get("/health")
def health():
    return {"status": "ok", "service": "sipp-authorization"}


def validar_api_key(api_key: str | None):
    if not AUTH_API_KEY:
        logging.error("AUTH_API_KEY no esta configurada.")
        raise HTTPException(status_code=503, detail="La API no esta configurada.")
    if not api_key or not hmac.compare_digest(api_key, AUTH_API_KEY):
        raise HTTPException(status_code=401, detail="API key invalida.")


@app.get("/")
def root():
    return {"status": "ok", "service": "sipp-authorization", "message": "Servidor activo."}


@app.post("/v1/terms-acceptances")
def registrar_aceptacion_condiciones(datos: TermsAcceptance, x_api_key: str | None = Header(default=None)):
    validar_api_key(x_api_key)
    try:
        enviar_correo_aceptacion(datos)
        return {"status": "REGISTRADA", "message": "Aceptacion registrada."}
    except Exception as exc:
        logging.exception("No se pudo registrar la aceptacion de condiciones")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/admin/access-requests/{request_id}/{accion}", response_class=HTMLResponse)
def confirmar_accion_admin(request_id: str, accion: str, token: str):
    acciones = {
        "aprobar": ("APROBADO", "Equipo aprobado."),
        "rechazar": ("RECHAZADO", "Solicitud rechazada."),
        "bloquear": ("BLOQUEADO", "Equipo bloqueado."),
        "desbloquear": ("EXPIRADO", "Equipo desbloqueado. Puede solicitar acceso nuevamente."),
    }
    if accion not in acciones or not token:
        raise HTTPException(status_code=400, detail="Accion invalida.")
    try:
        request_uuid = uuid.UUID(request_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Solicitud invalida.") from exc
    with conectar() as conexion:
        with conexion.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM access_requests
                   WHERE request_id = %s AND action_token_hash = %s
                     AND (action_expires_at IS NULL OR action_expires_at > %s)""",
                (request_uuid, token_hash(token), datetime.now(timezone.utc)),
            )
            if cursor.fetchone() is None:
                raise HTTPException(status_code=403, detail="Enlace invalido, usado o caducado.")
    titulo = acciones[accion][1]
    destino = html.escape(f"/admin/access-requests/{request_id}/{accion}?token={quote(token)}", quote=True)
    return (
        "<html><body><h2>SiPP</h2>"
        f"<p>{html.escape(titulo)}</p>"
        f"<form method='post' action='{destino}'><button type='submit'>Confirmar</button></form>"
        "</body></html>"
    )


@app.post("/admin/access-requests/{request_id}/{accion}", response_class=HTMLResponse)
def ejecutar_accion_admin(request_id: str, accion: str, token: str):
    acciones = {
        "aprobar": ("APROBADO", "Equipo aprobado."),
        "rechazar": ("RECHAZADO", "Solicitud rechazada."),
        "bloquear": ("BLOQUEADO", "Equipo bloqueado."),
        "desbloquear": ("EXPIRADO", "Equipo desbloqueado. Puede solicitar acceso nuevamente."),
    }
    if accion not in acciones or not token:
        raise HTTPException(status_code=400, detail="Accion invalida.")
    try:
        request_uuid = uuid.UUID(request_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Solicitud invalida.") from exc
    nuevo_estado, mensaje = acciones[accion]
    ahora = datetime.now(timezone.utc)
    with conectar() as conexion:
        with conexion.cursor() as cursor:
            cursor.execute(
                """UPDATE access_requests
                   SET status = %s, code_hash = CASE WHEN %s IN ('RECHAZADO', 'BLOQUEADO') THEN NULL ELSE code_hash END,
                       updated_at = %s
                   WHERE request_id = %s AND action_token_hash = %s
                     AND (action_expires_at IS NULL OR action_expires_at > %s)
                   RETURNING installation_id""",
                (nuevo_estado, nuevo_estado, ahora, request_uuid, token_hash(token), ahora),
            )
            fila = cursor.fetchone()
        if not fila:
            raise HTTPException(status_code=403, detail="Enlace invalido, usado o caducado.")
    return f"<html><body><h2>SiPP</h2><p>{html.escape(mensaje)}</p></body></html>"


@app.post("/v1/access-requests")
def crear_solicitud(datos: AccessRequest, x_api_key: str | None = Header(default=None)):
    validar_api_key(x_api_key)
    ahora = datetime.now(timezone.utc)
    try:
        with conectar() as conexion:
            with conexion.cursor() as cursor:
                cursor.execute(
                    """SELECT request_id, status, expires_at
                       FROM access_requests
                       WHERE installation_id = %s AND status IN ('PENDIENTE', 'BLOQUEADO')
                       ORDER BY created_at DESC LIMIT 1""",
                    (datos.installation_id,),
                )
                pendiente = cursor.fetchone()
                if pendiente and pendiente[1] == "BLOQUEADO":
                    raise HTTPException(status_code=403, detail="El equipo esta bloqueado.")
                if pendiente and not datos.force_new and pendiente[2] > ahora:
                    return fila_a_respuesta(pendiente)
                cursor.execute(
                    "UPDATE access_requests SET status = 'EXPIRADO', code_hash = NULL, updated_at = %s "
                    "WHERE installation_id = %s AND status = 'PENDIENTE'",
                    (ahora, datos.installation_id),
                )
                request_id = uuid.uuid4()
                expires_at = ahora + timedelta(minutes=CODE_MINUTES)
                code = f"{secrets.randbelow(1000000):06d}"
                token = secrets.token_urlsafe(32)
                action_expires_at = ahora + timedelta(minutes=ACTION_MINUTES)
                cursor.execute(
                    """INSERT INTO access_requests
                    (request_id, installation_id, device_name, windows_user, operating_system,
                     app_version, status, code_hash, expires_at, action_token_hash, action_expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, 'PENDIENTE', %s, %s, %s, %s)""",
                    (request_id, datos.installation_id, datos.device_name, datos.windows_user,
                     datos.operating_system, datos.app_version, codigo_hash(request_id, code), expires_at,
                     token_hash(token), action_expires_at),
                )
        try:
            enviar_correo(datos, request_id, code, expires_at, token)
        except RuntimeError as exc:
            logging.exception("No se pudo enviar el codigo por correo")
            raise HTTPException(status_code=503, detail="No se pudo enviar el codigo por correo.") from exc
        respuesta = fila_a_respuesta((request_id, "PENDIENTE", expires_at))
        return respuesta
    except HTTPException:
        raise
    except Exception as exc:
        logging.exception("No se pudo crear la solicitud")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/access-requests/{request_id}/verify")
def validar_codigo(request_id: str, datos: VerifyCode, x_api_key: str | None = Header(default=None)):
    validar_api_key(x_api_key)
    try:
        request_uuid = uuid.UUID(request_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Solicitud invalida.") from exc
    ahora = datetime.now(timezone.utc)
    try:
        with conectar() as conexion:
            with conexion.cursor() as cursor:
                cursor.execute(
                    """SELECT installation_id, status, code_hash, expires_at, used_at
                       FROM access_requests WHERE request_id = %s FOR UPDATE""",
                    (request_uuid,),
                )
                fila = cursor.fetchone()
                if not fila or fila[0] != datos.installation_id:
                    raise HTTPException(status_code=404, detail="Solicitud no encontrada.")
                if fila[1] not in ("PENDIENTE", "APROBADO") or fila[4] is not None:
                    raise HTTPException(status_code=409, detail="El codigo ya no esta disponible.")
                if fila[3] <= ahora:
                    cursor.execute(
                        "UPDATE access_requests SET status = 'EXPIRADO', code_hash = NULL, updated_at = %s WHERE request_id = %s",
                        (ahora, request_uuid),
                    )
                    raise HTTPException(status_code=410, detail="El codigo ha caducado.")
                esperado = codigo_hash(request_uuid, datos.code)
                if not hmac.compare_digest(str(fila[2]), esperado):
                    raise HTTPException(status_code=401, detail="Codigo incorrecto.")
                cursor.execute(
                    """UPDATE access_requests
                       SET status = 'APROBADO', used_at = %s, updated_at = %s
                       WHERE request_id = %s""",
                    (ahora, ahora, request_uuid),
                )
        return {"request_id": request_id, "status": "APROBADO", "message": "Equipo autorizado."}
    except HTTPException:
        raise
    except Exception as exc:
        logging.exception("No se pudo validar el codigo")
        raise HTTPException(status_code=500, detail="No se pudo validar el codigo.") from exc