# modules/scanner.py
"""
Orquesta todo el proceso de escaneo:
1. Ejecuta cryptolyze
2. Parse resultados
3. Analiza seguridad cuántica
4. Visualiza en consola
5. Guarda reporte
"""
import os
import time
from datetime import datetime, timezone
from core.utils import (
    run_command, cmd_exists, get_results_dir, delete_temp,
    log_info, log_error, log_success, log_warning,
    resolve_ips_with_fallback, format_duration_ms
)
from modules.parser import parse_cryptolyze_output
from modules.analyzer import analyze_quantum_safety, build_attack_surface
from modules.visualizer import render_compact_report
from modules.reporter import save_json_report

def run_scan(domain):
    """
    Ejecuta el escaneo completo para un dominio.
    Retorna código de salida (0=éxito, otros=error).
    """
    # Preparar directorios
    results_dir = get_results_dir("quantum")
    timestamp = datetime.now(timezone.utc).isoformat()
    
    raw_out_file = os.path.join(results_dir, f"cryptolyze_tls_all_{domain}.txt")
    report_json = os.path.join(results_dir, f"pqc_tls_{domain}.json")
    
    os.makedirs(os.path.dirname(raw_out_file), exist_ok=True)
    os.makedirs(os.path.dirname(report_json), exist_ok=True)
    
    # Verificar cryptolyze
    if not cmd_exists("cryptolyze"):
        log_error("'cryptolyze' no está disponible.")
        log_info("Instálalo con: quantum.py install")
        return 2
    
    # Ejecutar cryptolyze
    log_info(f"Escaneando: {domain}")
    t0 = time.time()
    
    try:
        stdout = run_command(f"cryptolyze tls all {domain}", 
                           capture_output=True, 
                           timeout=120)
    except Exception as e:
        log_error(f"Error ejecutando cryptolyze: {e}")
        return 2
    
    duration_ms = int((time.time() - t0) * 1000)
    log_info(f"Escaneo completado en {format_duration_ms(t0)}")
    
    # Verificar salida
    if not stdout:
        log_error("No se obtuvo salida de cryptolyze.")
        log_info("Posibles causas: Timeout, dominio inalcanzable, firewall")
        return 2
    
    # Guardar crudo
    try:
        with open(raw_out_file, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(stdout)
        log_success(f"Salida cruda guardada: {raw_out_file}")
    except Exception as e:
        log_error(f"No pude escribir la salida cruda: {e}")
        return 2
    
    # Limpiar temporales
    try:
        delete_temp()
    except Exception as e:
        log_warning(f"Limpieza temporal parcialmente fallida: {e}")
    
    # Verificar archivo
    if not os.path.isfile(raw_out_file) or os.path.getsize(raw_out_file) == 0:
        log_error(f"No se generó salida válida: {raw_out_file}")
        return 2
    
    # Parsear resultados
    try:
        artifacts = parse_cryptolyze_output(raw_out_file)
    except Exception as e:
        log_error(f"Error parseando resultados: {e}")
        return 2
    
    # Analizar seguridad cuántica
    analysis = analyze_quantum_safety(artifacts)
    
    # Construir superficie de ataque
    attack_surface = build_attack_surface(
        artifacts.get("named_curves", []),
        artifacts.get("supported_signature_algorithms", []),
        artifacts.get("certificate_algorithms", []),
        artifacts.get("ciphers_by_version", {})
    )
    
    # Obtener IPs resueltas
    ips = resolve_ips_with_fallback(domain)
    
    # Preparar datos para reporte
    report_data = {
        "schema_version": "1.0.0",
        "generator": {"name": "quantum-check", "version": "0.3.0"},
        "target": {"domain": domain, "port": 443, "sni": domain, "resolved_ips": ips},
        "scan": {"timestamp": timestamp, "duration_ms": duration_ms, "errors": []},
        "tool": "cryptolyze tls all",
        "artifacts": artifacts,
        "analysis": analysis,
        "attack_surface": attack_surface
    }
    
    # Mostrar en consola
    render_compact_report(artifacts, analysis, attack_surface)
    
    # Guardar JSON
    try:
        save_json_report(report_data, report_json)
        log_success(f"Reporte guardado: {report_json}")
    except Exception as e:
        log_error(f"Error guardando reporte JSON: {e}")
        return 2
    
    return 0