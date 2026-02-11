# modules/reporter.py
"""
Generación y guardado de reportes en JSON.
"""
import json
import os
from datetime import datetime
from typing import Dict

def save_json_report(report_data: Dict, file_path: str):
    """
    Guarda el reporte como JSON con formato bonito.
    
    Args:
        report_data: Diccionario con todos los datos del reporte
        file_path: Ruta donde guardar el archivo JSON
    """
    # Añadir metadatos de generación si no existen
    if "generation" not in report_data:
        report_data["generation"] = {
            "timestamp": datetime.now().isoformat(),
            "tool": "quantum-tls-analyzer",
            "version": "0.3.0"
        }
    
    # Asegurar directorio
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # Guardar con formato
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False, sort_keys=False)
    
    return file_path

def load_json_report(file_path: str) -> Dict:
    """
    Carga un reporte JSON existente.
    
    Args:
        file_path: Ruta al archivo JSON
    
    Returns:
        Diccionario con los datos del reporte
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"No se encontró el archivo: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return data

def generate_report_summary(report_data: Dict) -> str:
    """
    Genera un resumen textual del reporte.
    
    Args:
        report_data: Datos del reporte
    
    Returns:
        String con resumen formateado
    """
    target = report_data.get("target", {})
    analysis = report_data.get("analysis", {})
    artifacts = report_data.get("artifacts", {})
    
    domain = target.get("domain", "N/A")
    verdict = analysis.get("verdict", "UNKNOWN")
    confidence = analysis.get("confidence", 0.0)
    has_pqc_kem = analysis.get("has_pqc_kem", False)
    has_pqc_sig = analysis.get("has_pqc_sig", False)
    
    summary = f"""
=== RESUMEN DE ESCANEO ===
Dominio: {domain}
Veredicto: {verdict}
Confianza: {confidence:.2f}
KEM PQC detectado: {'Sí' if has_pqc_kem else 'No'}
Firmas PQC detectadas: {'Sí' if has_pqc_sig else 'No'}

=== INFORMACIÓN TLS ===
Versiones: {', '.join(artifacts.get('protocol_versions', []))}
Curvas soportadas: {len(artifacts.get('named_curves', []))}
Cifrados TLS 1.3: {len(artifacts.get('ciphers_by_version', {}).get('TLS1.3', []))}

=== CERTIFICADO ===
Subject: {artifacts.get('subject_cn', 'N/A')}
Issuer: {artifacts.get('issuer_cn', 'N/A')}
Días restantes: {artifacts.get('certificate_validity', {}).get('remaining_days', 'N/A')}
"""
    
    return summary

def export_as_markdown(report_data: Dict, output_path: str):
    """
    Exporta el reporte como documento Markdown.
    
    Args:
        report_data: Datos del reporte
        output_path: Ruta donde guardar el .md
    """
    target = report_data.get("target", {})
    analysis = report_data.get("analysis", {})
    artifacts = report_data.get("artifacts", {})
    attack_surface = report_data.get("attack_surface", [])
    
    domain = target.get("domain", "N/A")
    timestamp = report_data.get("scan", {}).get("timestamp", "")
    verdict = analysis.get("verdict", "UNKNOWN")
    
    markdown = f"""# Reporte Quantum TLS - {domain}

**Fecha**: {timestamp}  
**Dominio**: {domain}  
**Veredicto**: **{verdict}**

## Resumen de Seguridad Cuántica

**Confianza**: {analysis.get('confidence', 0.0):.2f}  
**KEM PQC**: {'✅ Sí' if analysis.get('has_pqc_kem') else '❌ No'}  
**Firmas PQC**: {'✅ Sí' if analysis.get('has_pqc_sig') else '❌ No'}

## Detalles TLS

### Versiones soportadas
{chr(10).join(f'- {v}' for v in artifacts.get('protocol_versions', []))}

### Curvas elípticas
{chr(10).join(f'- {c}' for c in artifacts.get('named_curves', []))}

### Cifrados TLS 1.3
{chr(10).join(f'- {c}' for c in artifacts.get('ciphers_by_version', {}).get('TLS1.3', []))}

## Certificado

**Subject**: {artifacts.get('subject_cn', 'N/A')}  
**Issuer**: {artifacts.get('issuer_cn', 'N/A')}  
**Algoritmo de firma**: {artifacts.get('leaf_signature_algorithm', 'N/A')}  
**Clave pública**: {artifacts.get('public_key_info', {}).get('key_type', 'N/A')} ({artifacts.get('public_key_info', {}).get('key_size_bits', 'N/A')} bits)  
**Válido hasta**: {artifacts.get('certificate_validity', {}).get('not_after', 'N/A')}  
**Días restantes**: {artifacts.get('certificate_validity', {}).get('remaining_days', 'N/A')}

## Superficie de Ataque Cuántico

| Componente | Algoritmo | Ataque | Riesgo |
|------------|-----------|---------|---------|
"""
    
    # Añadir filas de superficie de ataque
    for item in attack_surface:
        component = item.get("component", "")
        observed = item.get("observed", "")
        attack = item.get("quantum_attack", "")
        
        # Simplificar para tabla
        alg_short = ""
        if "Key Exchange" in component:
            alg_short = "ECDH/ECDHE"
        elif "Firmas" in component:
            alg_short = "RSA/ECDSA"
        elif "Cifrado" in component:
            if "AES_128" in observed:
                alg_short = "AES-128"
            elif "AES_256" in observed:
                alg_short = "AES-256"
            elif "CHACHA20" in observed:
                alg_short = "ChaCha20"
        
        risk = "ALTO" if "Shor" in attack else ("MEDIO" if "AES_128" in observed else "BAJO")
        
        markdown += f"| {component} | {alg_short} | {attack} | {risk} |\n"
    
    markdown += f"""

## Recomendaciones

"""
    
    # Añadir recomendaciones basadas en análisis
    reasons = analysis.get("reasons", [])
    for reason in reasons:
        if "recomendar" in reason.lower() or "preferir" in reason.lower() or "implementar" in reason.lower():
            markdown += f"- {reason}\n"
    
    markdown += f"""

---
*Generado por Quantum TLS Analyzer v0.3.0*
"""
    
    # Guardar
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)
    
    return output_path