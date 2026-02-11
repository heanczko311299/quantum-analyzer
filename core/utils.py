#!/usr/bin/env python3
# core/utils.py — Framework de utilidades mejorado
# Sin dependencias OSINT, solo funciones generales robustas

import os
import re
import shutil
import subprocess
import ipaddress
import contextlib
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# =====================================================
# 0) UTILIDADES GENERALES
# =====================================================

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')  # Regex más completa para ANSI

def strip_ansi(text: str) -> str:
    """
    Elimina secuencias ANSI de color/formato en 'text'.
    Versión mejorada con regex más completa.
    """
    if text is None:
        return ""
    return _ANSI_RE.sub("", str(text))


# =====================================================
# 1) NORMALIZACIÓN Y SANITIZACIÓN (MEJORADAS)
# =====================================================

def normalize_domain(domain):
    """
    Limpia y normaliza un dominio o URL.
    Versión mejorada: manejo mejor de subdominios y casos edge.
    """
    if not domain:
        return None

    d = str(domain).strip().lower()
    if not d or d in {"none", "null", "undefined", "null"}:
        return None

    # quitar "site:"
    if d.startswith("site:"):
        d = d[5:]

    # quitar wildcard (solo al inicio)
    if d.startswith("*."):
        d = d[2:]

    # quitar protocolo
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]

    # quitar ruta
    d = d.split("/")[0]

    # quitar puerto
    if ":" in d:
        d = d.split(":")[0]

    # quitar www SOLO si hay al menos un punto después
    if d.startswith("www.") and d.count('.') >= 2:
        d = d[4:]

    # validación mejorada
    if not re.match(r"^[a-z0-9.-]+$", d):
        return None
    if "." not in d:
        return None
    if d.startswith(".") or d.endswith("."):
        return None
    if ".." in d:
        return None

    return d


def sanitize_phrase(text):
    """
    Limpia comillas para evitar romper comandos shell.
    """
    if text is None:
        return ""
    return str(text).replace('"', r'\"').replace("'", r"\'").strip()


def sanitize_filename(name):
    """
    Limpia nombres de archivo para evitar path traversal.
    Versión mejorada: elimina solo caracteres inválidos en sistemas de archivos.
    """
    if not name:
        return "output"

    name = str(name)
    # Eliminar caracteres inválidos en Windows/Linux
    name = re.sub(r'[<>:"/\\|?*]', "", name)
    # Eliminar puntos dobles y path traversal
    name = name.replace("..", "")
    # Limitar longitud
    if len(name) > 100:
        name = name[:100]

    return name or "output"


def validate_domain_input(user_input):
    """
    Valida dominio o URL ingresado por el usuario.
    """
    if not user_input:
        return None
    return normalize_domain(user_input)


# =====================================================
# 2) VALIDACIONES ADICIONALES
# =====================================================

def is_valid_ip(ip_str):
    """
    Valida si una cadena es una IPv4 o IPv6 válida.
    """
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def ask_yesno(question, default=False):
    """
    Pregunta sí/no con respuesta por defecto.
    
    Args:
        question: Texto de la pregunta
        default: True para [Y/n], False para [y/N]
    
    Returns:
        bool: True para sí, False para no
    """
    choices = "[Y/n]" if default else "[y/N]"
    while True:
        resp = input(f"{Fore.CYAN}{question} {choices}{Style.RESET_ALL}: ").strip().lower()
        
        if not resp:
            return default
        
        if resp in ("y", "yes", "s", "sí", "si"):
            return True
        elif resp in ("n", "no"):
            return False
        else:
            print(f"{Fore.YELLOW}Respuesta inválida. Usa 'y' o 'n'{Style.RESET_ALL}")


# =====================================================
# 3) LOGGING CONSISTENTE
# =====================================================

def log_info(msg):
    """Log de información."""
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")


def log_error(msg):
    """Log de error."""
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")


def log_warning(msg):
    """Log de advertencia."""
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {msg}")


def log_success(msg):
    """Log de éxito."""
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")


# =====================================================
# 4) GESTOR DE CARPETAS (RESULTS) - MEJORADO
# =====================================================

class AppConfig:
    """
    Singleton para configuración de la aplicación.
    Reemplaza la variable global SESSION_TIMESTAMP.
    """
    _instance = None
    session_timestamp = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls.session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return cls._instance
    
    @classmethod
    def get_timestamp(cls):
        """Obtiene timestamp único por sesión."""
        if cls.session_timestamp is None:
            cls.session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return cls.session_timestamp


def get_results_base_dir():
    """
    Obtiene el directorio base de resultados.
    Verifica permisos de escritura.
    """
    base = os.path.abspath("results")
    try:
        os.makedirs(base, exist_ok=True)
        # Test de escritura
        test_file = os.path.join(base, ".write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
    except (OSError, IOError) as e:
        log_error(f"No se puede escribir en {base}: {e}")
        raise
    return base


def get_results_dir(module_name):
    """
    results/<module>/<timestamp>/
    Versión mejorada con validación de longitud y limpieza opcional.
    """
    base = get_results_base_dir()
    
    m = str(module_name or "").lower().strip()
    m = re.sub(r"[^a-z0-9_\-]", "", m)
    if not m:
        m = "misc"
    
    # Limitar longitud para evitar problemas con paths largos
    if len(m) > 50:
        m = m[:50]
        log_warning(f"Nombre de módulo truncado a {m}")
    
    tool_root = os.path.join(base, m)
    os.makedirs(tool_root, exist_ok=True)
    
    timestamp = AppConfig.get_timestamp()
    final = os.path.join(tool_root, timestamp)
    os.makedirs(final, exist_ok=True)
    
    log_info(f"Directorio de resultados: {final}")
    return final


# =====================================================
# 5) SISTEMA DE COMANDOS - MEJORADO CON TIMEOUT
# =====================================================

def cmd_exists(cmd_name):
    """Verifica si un comando existe en PATH."""
    return shutil.which(cmd_name) is not None


def run_command(command, capture_output=False, timeout=30):
    """
    Ejecuta comando shell con timeout.
    
    Args:
        command: Comando a ejecutar
        capture_output: True para capturar salida
        timeout: Timeout en segundos (None para sin timeout)
    
    Returns:
        str si capture_output=True, de lo contrario None
    """
    log_info(f"Ejecutando: {command[:80]}{'...' if len(command) > 80 else ''}")
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=capture_output,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
        )
        
        if capture_output:
            output = (result.stdout or "").strip()
            if result.stderr and not result.stdout:
                output = (result.stderr or "").strip()
            
            if result.returncode != 0:
                log_warning(f"Comando exitoso con código {result.returncode}")
                if result.stderr:
                    log_warning(f"Stderr: {result.stderr[:200]}")
            
            return output
        
        # Si no capture_output, manejar salida normalmente
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            log_error("Error ejecutando comando.")
            if err:
                log_error(err[:500])
        elif result.stdout and result.stdout.strip():
            print(result.stdout)
        elif result.stderr and result.stderr.strip():
            log_warning("Salida por stderr:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        log_error(f"Comando excedió timeout de {timeout}s")
        return "" if capture_output else None
    except Exception as e:
        log_error(f"No se pudo ejecutar el comando: {e}")
        return "" if capture_output else None


# =====================================================
# 6) DELETE TEMP — MÁS SEGURO
# =====================================================

def delete_temp(patterns=None):
    """
    Elimina archivos temporales solo en la raíz del proyecto.
    Versión más segura con verificaciones.
    """
    if patterns is None:
        patterns = [".tmp", ".temp", ".log", ".bak"]
    
    root = os.path.abspath(os.getcwd())
    
    # Verificar que estamos en el directorio del proyecto
    required_files = ["quantum.py", "core", "results"]
    found_files = 0
    for item in required_files:
        if os.path.exists(os.path.join(root, item)):
            found_files += 1
    
    if found_files < 2:  # Requerir al menos 2 de los indicadores
        log_warning("No se detectó directorio del proyecto, omitiendo limpieza de temporales")
        return
    
    deleted_count = 0
    for item in os.listdir(root):
        full_path = os.path.join(root, item)
        
        if os.path.isdir(full_path):
            continue
        
        # Verificar si coincide con patrones
        should_delete = False
        for pattern in patterns:
            if item.endswith(pattern):
                should_delete = True
                break
        
        if should_delete:
            try:
                os.remove(full_path)
                deleted_count += 1
                log_info(f"Eliminado temporal: {item}")
            except Exception as e:
                log_warning(f"No se pudo eliminar {item}: {e}")
    
    if deleted_count > 0:
        log_info(f"Limpieza completada: {deleted_count} archivos eliminados")
    else:
        log_info("No se encontraron archivos temporales para limpiar")


# =====================================================
# 7) CONTEXT MANAGERS ÚTILES
# =====================================================

@contextlib.contextmanager
def temp_directory():
    """
    Context manager para directorio temporal.
    Crea directorio temporal y lo limpia al salir.
    """
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="quantum_")
    log_info(f"Directorio temporal creado: {tmpdir}")
    
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
            log_info(f"Directorio temporal eliminado: {tmpdir}")
        except Exception as e:
            log_warning(f"No se pudo eliminar directorio temporal: {e}")


def cleanup_old_results(days_to_keep=7):
    """
    Limpia resultados antiguos automáticamente.
    
    Args:
        days_to_keep: Número de días a mantener
    """
    try:
        base = get_results_base_dir()
        now = datetime.now()
        
        for module_dir in os.listdir(base):
            module_path = os.path.join(base, module_dir)
            if not os.path.isdir(module_path):
                continue
            
            for timestamp_dir in os.listdir(module_path):
                try:
                    # Parsear timestamp del formato YYYY-MM-DD_HH-MM-SS
                    dir_time = datetime.strptime(timestamp_dir, "%Y-%m-%d_%H-%M-%S")
                    age = (now - dir_time).days
                    
                    if age > days_to_keep:
                        dir_to_remove = os.path.join(module_path, timestamp_dir)
                        shutil.rmtree(dir_to_remove, ignore_errors=True)
                        log_info(f"Eliminado resultado antiguo ({age} días): {dir_to_remove}")
                except ValueError:
                    # Directorio no tiene formato de timestamp, ignorar
                    continue
    except Exception as e:
        log_warning(f"No se pudo limpiar resultados antiguos: {e}")


# =====================================================
# 8) FUNCIONES AUXILIARES PARA QUANTUM
# =====================================================

def resolve_ips_with_fallback(domain):
    """
    Resuelve IPs de un dominio con fallback a múltiples métodos.
    """
    import socket
    
    ips = set()
    
    # Método 1: socket.getaddrinfo (IPv4 + IPv6)
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(domain, 443, 
                                          family=family, 
                                          type=socket.SOCK_STREAM)
                for info in infos:
                    addr = info[4][0]
                    if is_valid_ip(addr):
                        ips.add(addr)
            except (socket.gaierror, socket.error):
                continue
    except Exception:
        pass
    
    # Método 2: Usar nslookup/dig si disponible (solo para mostrar)
    if not ips:
        log_warning(f"No se pudieron resolver IPs para {domain}")
    
    return sorted(ips)


def format_duration_ms(start_time, end_time=None):
    """
    Formatea duración en milisegundos a string legible.
    """
    import time
    if end_time is None:
        end_time = time.time()
    
    duration_ms = int((end_time - start_time) * 1000)
    
    if duration_ms < 1000:
        return f"{duration_ms}ms"
    elif duration_ms < 60000:
        return f"{duration_ms/1000:.2f}s"
    else:
        minutes = duration_ms // 60000
        seconds = (duration_ms % 60000) / 1000
        return f"{minutes}m {seconds:.1f}s"
