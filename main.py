import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import smtplib
import uuid
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

import psycopg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


logging.basicConfig(level=logging.INFO)
app = FastAPI(title="SiPP Authorization API", version="2.3.0")
CODE_MINUTES = 10
AUTH_CODE_SECRET_LOCAL = "sipp-local-auth-secret-2.3"
SMTP_HOST_LOCAL = "smtp-relay.brevo.com"
SMTP_PORT_LOCAL = 587
SMTP_USER_LOCAL = "b81263001@smtp-brevo.com"
SMTP_EMAIL_LOCAL = "prom2219zip@gmail.com"
MODO_LOCAL_SIN_CORREO = False
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def configuracion_correo():
    servidor_smtp = os.getenv("SMTP_HOST", SMTP_HOST_LOCAL)
    puerto_smtp = int(os.getenv("SMTP_PORT", str(SMTP_PORT_LOCAL)))
    cuenta_smtp = os.getenv("SMTP_USER", SMTP_USER_LOCAL)
    contraseña_smtp = os.getenv("SMTP_PASSWORD", "").strip()
    remitente = os.getenv("SMTP_FROM", SMTP_EMAIL_LOCAL)
    destinatario = os.getenv("SMTP_TO", SMTP_EMAIL_LOCAL)
    if not contraseña_smtp:
        raise RuntimeError("Configure SMTP_PASSWORD.")
    return servidor_smtp, puerto_smtp, cuenta_smtp, contraseña_smtp, remitente, destinatario


def enviar_correo_brevo_api(asunto, texto, html_cuerpo, remitente, destinatario):
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Configure BREVO_API_KEY.")
    cuerpo = json.dumps(
        {
            "sender": {"email": remitente},
            "to": [{"email": destinatario}],
            "subject": asunto,
            "textContent": texto,
            "htmlContent": html_cuerpo,
        }
    ).encode("utf-8")
    solicitud = Request(
        BREVO_API_URL,
        data=cuerpo,
        headers={"accept": "application/json", "api-key": api_key, "content-type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(solicitud, timeout=15) as respuesta:
            if respuesta.status not in (200, 201, 202):
                raise RuntimeError(f"Brevo API devolvio HTTP {respuesta.status}.")
    except Exception as exc:
        raise RuntimeError(f"No se pudo enviar el correo por Brevo API: {exc}") from exc


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


def fila_a_respuesta(fila):
    return {
        "request_id": str(fila[0]),
        "status": fila[1],
        "expires_at": fila[2].isoformat() if fila[2] else None,
        "message": "Solicitud enviada" if fila[1] == "PENDIENTE" else f"Acceso {fila[1].lower()}",
    }


def enviar_correo(datos, request_id, code, expires_at):
    if os.getenv("BREVO_API_KEY", "").strip():
        remitente = SMTP_EMAIL_LOCAL
        cuerpo = f"Codigo de autorizacion: {code}. Caduca en {CODE_MINUTES} minutos."
        html_cuerpo = f"<h2>Solicitud de acceso a SiPP</h2><p><strong>Codigo de autorizacion: {html.escape(code)}</strong></p><p>Caduca en {CODE_MINUTES} minutos.</p>"
        enviar_correo_brevo_api(f"SiPP: solicitud de acceso ({datos.device_name})", cuerpo, html_cuerpo, remitente, remitente)
        return
    servidor_smtp, puerto_smtp, cuenta_smtp, contraseña_smtp, remitente, destinatario = configuracion_correo()
    cuerpo = f"""
    <h2>Solicitud de acceso a SiPP</h2>
    <p>Una computadora solicita permiso para usar SiPP.</p>
    <ul>
      <li>Equipo: {html.escape(datos.device_name)}</li>
      <li>Usuario: {html.escape(datos.windows_user)}</li>
      <li>Sistema: {html.escape(datos.operating_system)}</li>
      <li>Version: {html.escape(datos.app_version)}</li>
      <li>Identificador: {html.escape(datos.installation_id)}</li>
    </ul>
    <p><strong>Codigo de autorizacion: {html.escape(code)}</strong></p>
    <p>El codigo caduca en {CODE_MINUTES} minutos y solo puede usarse una vez.</p>
    <p>Caduca: {html.escape(expires_at.isoformat())}</p>
    """
    mensaje = EmailMessage()
    mensaje["From"] = remitente
    mensaje["To"] = destinatario
    mensaje["Subject"] = f"SiPP: solicitud de acceso ({datos.device_name})"
    mensaje.set_content("Su cliente de correo no admite HTML.")
    mensaje.add_alternative(cuerpo, subtype="html")
    try:
        conexion_smtp = smtplib.SMTP_SSL if puerto_smtp == 465 else smtplib.SMTP
        with conexion_smtp(servidor_smtp, puerto_smtp, timeout=15) as conexion:
            if puerto_smtp != 465:
                conexion.starttls()
            conexion.login(cuenta_smtp, contraseña_smtp)
            conexion.send_message(mensaje)
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError(f"No se pudo enviar el correo de autorizacion: {exc}") from exc


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
    if os.getenv("BREVO_API_KEY", "").strip():
        html_cuerpo = f"<h2>Aceptacion de condiciones de SiPP</h2><h3>Equipo que accedio</h3>{detalles_equipo}<pre>{html.escape(datos.terms_text)}</pre>"
        enviar_correo_brevo_api("SiPP: condiciones aceptadas", "Se aceptaron las condiciones de uso de SiPP.", html_cuerpo, SMTP_EMAIL_LOCAL, SMTP_EMAIL_LOCAL)
        return
    servidor_smtp, puerto_smtp, cuenta_smtp, contraseña_smtp, remitente, destinatario = configuracion_correo()
    cuerpo = f"""
    <h2>Aceptacion de condiciones de SiPP</h2>
    <p>Un usuario acepto las condiciones de uso de SiPP.</p>
    <h3>Equipo que accedio</h3>
    {detalles_equipo}
    <h3>Texto aceptado</h3>
    <pre>{html.escape(datos.terms_text)}</pre>
    """
    mensaje = EmailMessage()
    mensaje["From"] = remitente
    mensaje["To"] = destinatario
    mensaje["Subject"] = f"SiPP: condiciones aceptadas ({datos.windows_user})"
    mensaje.set_content("Se aceptaron las condiciones de uso de SiPP.")
    mensaje.add_alternative(cuerpo, subtype="html")
    try:
        conexion_smtp = smtplib.SMTP_SSL if puerto_smtp == 465 else smtplib.SMTP
        with conexion_smtp(servidor_smtp, puerto_smtp, timeout=15) as conexion:
            if puerto_smtp != 465:
                conexion.starttls()
            conexion.login(cuenta_smtp, contraseña_smtp)
            conexion.send_message(mensaje)
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError(f"No se pudo enviar el aviso de aceptacion: {exc}") from exc


@app.get("/health")
def health():
    return {"status": "ok", "service": "sipp-authorization"}


@app.post("/v1/terms-acceptances")
def registrar_aceptacion_condiciones(datos: TermsAcceptance):
    try:
        if not MODO_LOCAL_SIN_CORREO:
            enviar_correo_aceptacion(datos)
        return {"status": "REGISTRADA", "message": "Aceptacion registrada."}
    except Exception as exc:
        logging.exception("No se pudo registrar la aceptacion de condiciones")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/access-requests")
def crear_solicitud(datos: AccessRequest):
    ahora = datetime.now(timezone.utc)
    try:
        with conectar() as conexion:
            with conexion.cursor() as cursor:
                cursor.execute(
                    """SELECT request_id, status, expires_at
                       FROM access_requests
                       WHERE installation_id = %s AND status = 'PENDIENTE'
                       ORDER BY created_at DESC LIMIT 1""",
                    (datos.installation_id,),
                )
                pendiente = cursor.fetchone()
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
                cursor.execute(
                    """INSERT INTO access_requests
                    (request_id, installation_id, device_name, windows_user, operating_system,
                     app_version, status, code_hash, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, 'PENDIENTE', %s, %s)""",
                    (request_id, datos.installation_id, datos.device_name, datos.windows_user,
                     datos.operating_system, datos.app_version, codigo_hash(request_id, code), expires_at),
                )
        correo_enviado = True
        if not MODO_LOCAL_SIN_CORREO:
            try:
                enviar_correo(datos, request_id, code, expires_at)
            except RuntimeError:
                correo_enviado = False
                logging.warning("No se envio el correo; se muestra el codigo en modo local.")
        respuesta = fila_a_respuesta((request_id, "PENDIENTE", expires_at))
        if not correo_enviado:
            respuesta["code"] = code
            respuesta["message"] = "Modo local: use el codigo mostrado en SiPP."
        return respuesta
    except HTTPException:
        raise
    except Exception as exc:
        logging.exception("No se pudo crear la solicitud")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/access-requests/{request_id}/verify")
def validar_codigo(request_id: str, datos: VerifyCode):
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
                if fila[1] != "PENDIENTE" or fila[4] is not None:
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