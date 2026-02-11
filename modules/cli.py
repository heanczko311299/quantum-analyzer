# modules/cli.py
"""
Manejo de argumentos CLI con comportamiento exacto:
  - ./quantum.py           → ayuda
  - ./quantum.py help     → ayuda
  - ./quantum.py install  → instala de requirements.txt
  - ./quantum.py run      → pide dominio (3 intentos max)
  - ./quantum.py run <dom>→ si inválido, error y sale
"""
import sys
import subprocess
from colorama import Fore, Style
from core.banner import banner
from core.utils import (
    log_info, log_error, log_success, log_warning,
    validate_domain_input, normalize_domain
)
from modules.scanner import run_scan

def _show_help():
    """Muestra ayuda de uso."""
    help_text = f"""
{banner()}
{Fore.CYAN}USO:{Style.RESET_ALL}
  quantum.py                    # Muestra esta ayuda
  quantum.py help              # Muestra esta ayuda
  quantum.py install           # Instala dependencias (requirements.txt)
  quantum.py run [dominio]     # Escanea un dominio

{Fore.CYAN}EJEMPLOS:{Style.RESET_ALL}
  quantum.py run google.com
  quantum.py run
  quantum.py install

{Fore.CYAN}NOTAS:{Style.RESET_ALL}
  - Sin dominio: pide interactivo (3 intentos máximo)
  - Dominio inválido: error y sale inmediatamente
  - Resultados en: results/quantum/
"""
    print(help_text)
    return 0

def _install_dependencies():
    """
    Instalador profesional para Quantum TLS Analyzer.
    Busca Python → busca/instala pipx → instala herramientas con pipx.
    """
    import shutil
    import platform
    import subprocess
    import sys
    import os
    from pathlib import Path
    
    print(Fore.CYAN + "╔══════════════════════════════════════════╗")
    print(Fore.CYAN + "║   QUANTUM TLS - INSTALADOR (pipx)        ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════╝" + Style.RESET_ALL)
    
    # ===========================================================================
    # 1. DETECTAR PYTHON
    # ===========================================================================
    print(Fore.WHITE + "\n[1/4] Buscando Python..." + Style.RESET_ALL)
    
    python_cmd = None
    python_candidates = []
    
    # Orden de preferencia
    if platform.system().lower().startswith("win"):
        python_candidates = ["py", "python", "python3"]
    else:
        python_candidates = ["python3", "python"]
    
    for cmd in python_candidates:
        if shutil.which(cmd) is not None:
            # Verificar que sea Python 3
            try:
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if "Python 3" in result.stdout or "Python 3" in result.stderr:
                    python_cmd = cmd
                    version = result.stdout.strip() or result.stderr.strip()
                    print(Fore.GREEN + f"   ✓ Python encontrado: {version}" + Style.RESET_ALL)
                    break
            except:
                continue
    
    if not python_cmd:
        print(Fore.RED + "   ✗ Python 3 no encontrado" + Style.RESET_ALL)
        print(Fore.YELLOW + "\n   SOLUCIÓN: Instala Python desde:" + Style.RESET_ALL)
        print("   • Windows: https://python.org/downloads")
        print("   • Ubuntu/Debian: sudo apt install python3 python3-pip")
        print("   • RHEL/Fedora: sudo dnf install python3 python3-pip")
        print("   • macOS: brew install python")
        print(Fore.YELLOW + "\n   Asegúrate de marcar 'Add Python to PATH' en Windows." + Style.RESET_ALL)
        return 1
    
    # ===========================================================================
    # 2. DETECTAR O INSTALAR PIPX
    # ===========================================================================
    print(Fore.WHITE + "\n[2/4] Configurando pipx..." + Style.RESET_ALL)
    
    pipx_installed = shutil.which("pipx") is not None
    
    if not pipx_installed:
        print(Fore.YELLOW + "   ℹ pipx no encontrado. Instalando..." + Style.RESET_ALL)
        
        # Instalar pipx con pip (--user para no requerir admin)
        install_cmd = [python_cmd, "-m", "pip", "install", "--user", "pipx"]
        
        try:
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                print(Fore.RED + "   ✗ Error instalando pipx" + Style.RESET_ALL)
                if "Permission denied" in result.stderr:
                    print(Fore.YELLOW + "   ℹ Intenta con permisos de administrador:" + Style.RESET_ALL)
                    if platform.system().lower().startswith("win"):
                        print("      Ejecuta como Administrador")
                    else:
                        print("      sudo pip install pipx")
                return 1
            
            # Asegurar que pipx está en PATH
            ensurepath_cmd = [python_cmd, "-m", "pipx", "ensurepath"]
            subprocess.run(ensurepath_cmd, capture_output=True, text=True)
            
            # Recargar PATH (aproximación)
            if platform.system().lower().startswith("win"):
                pipx_path = Path.home() / ".local" / "bin"
                if pipx_path.exists():
                    os.environ["PATH"] = str(pipx_path) + ";" + os.environ["PATH"]
            
            print(Fore.GREEN + "   ✓ pipx instalado correctamente" + Style.RESET_ALL)
            
        except subprocess.TimeoutExpired:
            print(Fore.RED + "   ✗ Timeout instalando pipx" + Style.RESET_ALL)
            return 1
        except Exception as e:
            print(Fore.RED + f"   ✗ Error: {e}" + Style.RESET_ALL)
            return 1
    else:
        print(Fore.GREEN + "   ✓ pipx ya está instalado" + Style.RESET_ALL)
    
    # Verificar pipx funcional
    try:
        pipx_version = subprocess.run(
            ["pipx", "--version"],
            capture_output=True,
            text=True
        )
        if pipx_version.returncode == 0:
            print(Fore.GREEN + f"   ✓ Versión: {pipx_version.stdout.strip()}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "   ℹ pipx necesita reinicio de terminal" + Style.RESET_ALL)
    except:
        print(Fore.YELLOW + "   ℹ Reinicia la terminal para usar pipx" + Style.RESET_ALL)
    
    # ===========================================================================
    # 3. INSTALAR HERRAMIENTAS CON PIPX (SOLO LAS NECESARIAS)
    # ===========================================================================
    print(Fore.WHITE + "\n[3/4] Instalando herramientas..." + Style.RESET_ALL)
    
    # SOLO estas herramientas necesitan pipx
    herramientas_pipx = [
        ("cryptolyzer", "cryptolyze", "Análisis TLS"),
        ("tabulate", None, "Tablas formateadas")
    ]
    
    for pkg_name, bin_name, desc in herramientas_pipx:
        print(Fore.CYAN + f"   • {desc} ({pkg_name})..." + Style.RESET_ALL)
        
        # Verificar si ya está instalado
        try:
            list_cmd = ["pipx", "list"]
            result = subprocess.run(list_cmd, capture_output=True, text=True)
            if pkg_name in result.stdout:
                print(Fore.GREEN + f"     ✓ Ya instalado" + Style.RESET_ALL)
                continue
        except:
            pass
        
        # Instalar con pipx
        try:
            install_cmd = ["pipx", "install", pkg_name]
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                print(Fore.GREEN + f"     ✓ Instalado correctamente" + Style.RESET_ALL)
            else:
                # pipx puede fallar si ya está instalado de otra forma
                if "already seems to be installed" in result.stderr:
                    print(Fore.YELLOW + f"     ℹ Ya estaba instalado" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"     ✗ Error: {result.stderr[:100]}..." + Style.RESET_ALL)
                    # Continuar con otras herramientas
                    
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"     ✗ Timeout instalando {pkg_name}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"     ✗ Error: {e}" + Style.RESET_ALL)
    
    # ===========================================================================
    # 4. VERIFICAR INSTALACIÓN COMPLETA
    # ===========================================================================
    print(Fore.WHITE + "\n[4/4] Verificando instalación..." + Style.RESET_ALL)
    
    # Verificar cryptolyze (la herramienta crítica)
    cryptolyze_ok = False
    if shutil.which("cryptolyze"):
        try:
            result = subprocess.run(
                ["cryptolyze", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version_line = result.stdout.strip().split('\n')[0]
                print(Fore.GREEN + f"   ✓ cryptolyze: {version_line}" + Style.RESET_ALL)
                cryptolyze_ok = True
        except:
            pass
    
    if not cryptolyze_ok:
        print(Fore.YELLOW + "   ℹ cryptolyze no está en PATH" + Style.RESET_ALL)
        print(Fore.YELLOW + "   ℹ Puede necesitar:" + Style.RESET_ALL)
        print(Fore.YELLOW + "     • Reiniciar la terminal" + Style.RESET_ALL)
        print(Fore.YELLOW + "     • Ejecutar: pipx ensurepath" + Style.RESET_ALL)
    
    # Verificar módulos Python (colorama ya viene con Python o se instala con pip normal)
    try:
        # Intentar importar colorama (debería estar o instalarse fácilmente)
        import colorama
        print(Fore.GREEN + f"   ✓ colorama: {colorama.__version__}" + Style.RESET_ALL)
    except ImportError:
        print(Fore.YELLOW + "   ℹ colorama no encontrado" + Style.RESET_ALL)
        print(Fore.YELLOW + "   ℹ Se instalará automáticamente al ejecutar quantum.py" + Style.RESET_ALL)
    
    try:
        import tabulate
        print(Fore.GREEN + f"   ✓ tabulate disponible" + Style.RESET_ALL)
    except ImportError:
        print(Fore.RED + "   ✗ tabulate no importable (se necesitan tablas)" + Style.RESET_ALL)
        print(Fore.YELLOW + "   ℹ Instala manualmente: pip install tabulate" + Style.RESET_ALL)
    
    # ===========================================================================
    # RESUMEN FINAL
    # ===========================================================================
    print(Fore.CYAN + "\n" + "═" * 50 + Style.RESET_ALL)
    
    if cryptolyze_ok:
        print(Fore.GREEN + "✅ INSTALACIÓN COMPLETADA" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠ INSTALACIÓN PARCIAL - REINICIA LA TERMINAL" + Style.RESET_ALL)
    
    print(Fore.CYAN + "═" * 50 + Style.RESET_ALL)
    
    print(Fore.WHITE + "\nPARA USAR:" + Style.RESET_ALL)
    print(Fore.YELLOW + "  ./quantum.py run google.com" + Style.RESET_ALL)
    print(Fore.YELLOW + "  ./quantum.py run               # Modo interactivo" + Style.RESET_ALL)
    
    print(Fore.WHITE + "\nSI CRYPTOLYZE NO FUNCIONA:" + Style.RESET_ALL)
    if platform.system().lower().startswith("win"):
        print(Fore.YELLOW + "  • Reinicia PowerShell/CMD" + Style.RESET_ALL)
        print(Fore.YELLOW + "  • O agrega manualmente a PATH:" + Style.RESET_ALL)
        print(Fore.YELLOW + "    %USERPROFILE%\\.local\\bin" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "  • Reinicia la terminal" + Style.RESET_ALL)
        print(Fore.YELLOW + "  • O ejecuta: pipx ensurepath" + Style.RESET_ALL)
        print(Fore.YELLOW + "  • O añade a ~/.bashrc o ~/.zshrc:" + Style.RESET_ALL)
        print(Fore.YELLOW + "    export PATH=\"$HOME/.local/bin:$PATH\"" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\n" + "═" * 50 + Style.RESET_ALL)
    
    return 0

def _prompt_domain_interactive():
    """
    Pide dominio interactivo con 3 intentos máximo.
    Devuelve: dominio válido o None si falla.
    """
    max_attempts = 3
    
    for attempt in range(1, max_attempts + 1):
        raw = input(Fore.WHITE + f"[USER] Dominio o URL objetivo (ej: ejemplo.com) [{attempt}/{max_attempts}]: " + Style.RESET_ALL).strip()
        
        # Entrada vacía no cuenta como intento
        if not raw:
            log_error("Dominio no puede estar vacío.")
            continue
        
        # Validar dominio
        dom = validate_domain_input(raw)
        if dom:
            normalized = normalize_domain(dom)
            log_info(f"Dominio validado: {normalized}")
            return normalized
        
        # Dominio inválido
        log_error(f"Dominio/URL inválido: '{raw[:50]}{'...' if len(raw) > 50 else ''}'")
        
        if attempt == max_attempts:
            log_error("¡MÁXIMO DE INTENTOS ALCANZADO!")
        elif attempt < max_attempts:
            log_info(f"Te quedan {max_attempts - attempt} intento(s).")
    
    log_error("Saliendo de la aplicación.")
    return None

def _run_scan_cli(domain_arg=None):
    """
    Ejecuta escaneo en modo CLI.
    domain_arg: None (pide interactivo) o string (dominio directo)
    """
    domain = None
    
    if domain_arg:
        # Modo directo: validar y si falla, error inmediato
        dom = validate_domain_input(domain_arg)
        if dom:
            domain = normalize_domain(dom)
            log_info(f"Dominio validado: {domain}")
        else:
            log_error(f"Dominio inválido: '{domain_arg}'")
            log_error("Saliendo de la aplicación.")
            return 1
    else:
        # Modo interactivo (3 intentos máximo)
        print(banner())
        domain = _prompt_domain_interactive()
        if not domain:
            return 1
    
    # Ejecutar escaneo
    log_info(f"Iniciando escaneo de: {domain}")
    exit_code = run_scan(domain)
    
    return exit_code if isinstance(exit_code, int) else 0

def handle_cli_args():
    """
    Maneja todos los argumentos CLI.
    Retorna código de salida.
    """
    if len(sys.argv) < 2:
        # ./quantum.py sin argumentos → ayuda
        _show_help()
        return 0
    
    command = sys.argv[1].lower()
    
    if command in ["help", "--help", "-h"]:
        _show_help()
        return 0
    
    elif command == "install":
        return _install_dependencies()
    
    elif command == "run":
        domain_arg = sys.argv[2] if len(sys.argv) > 2 else None
        return _run_scan_cli(domain_arg)
    
    else:
        log_error(f"Comando no válido: '{command}'")
        print(f"\nUsa: {sys.argv[0]} help")
        return 1
