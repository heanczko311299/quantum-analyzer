# modules/parser.py
"""
Parsing de la salida de cryptolyze.
Extrae: curvas, protocolos, cifrados, certificados, etc.
"""
import re
import json
import os
from typing import List, Dict, Tuple, Optional

# Regex para limpieza ANSI
ANSI = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Patrones para detección
DIGICERT_HYBRID_CA = re.compile(r'^DigiCert TLS Hybrid ECC SHA384 2020 CA\d+$', re.IGNORECASE)
HYBRID_WORD = re.compile(r'\bhybrid\b', re.IGNORECASE)

def _clean_ansi(text: Optional[str]) -> str:
    """Elimina secuencias ANSI."""
    if text is None:
        return ""
    return ANSI.sub("", str(text))

def _extract_issuer_cn(text: str) -> str:
    """Extrae Common Name del issuer del certificado."""
    t = _clean_ansi(text)
    m = re.search(r'Issuer:\s*(?:.|\n)*?Common Name:\s*([^\n]+)', t, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def _extract_subject_cn(text: str) -> str:
    """Extrae Common Name del subject del certificado."""
    t = _clean_ansi(text)
    m = re.search(r'Subject:\s*(?:.|\n)*?Common Name:\s*([^\n]+)', t, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def _extract_named_curves(text: str) -> List[str]:
    """Extrae curvas elípticas soportadas."""
    curves = set()
    block_re = re.compile(r'#\s*Supported\s*Elliptic\s*Curves.*?(?:\n#|\Z)', 
                         flags=re.IGNORECASE | re.DOTALL)
    m = block_re.search(_clean_ansi(text))
    block = m.group(0) if m else ""

    if block:
        for line in block.splitlines():
            line = line.strip()
            m_item = re.search(r'^\*?\s*\d+\.\s+([A-Za-z0-9\-\_]+)$', line)
            if m_item:
                curves.add(m_item.group(1))
            else:
                m_curve = re.search(
                    r'\b(prime256v1|curve25519|secp256r1|secp384r1|secp521r1|x25519|x448|p-256|p-384|p-521)\b',
                    line, re.IGNORECASE)
                if m_curve:
                    curves.add(m_curve.group(1))

    if not curves:
        for m2 in re.finditer(
            r'\b(prime256v1|curve25519|secp256r1|secp384r1|secp521r1|x25519|x448|p-256|p-384|p-521)\b',
            _clean_ansi(text), flags=re.IGNORECASE):
            curves.add(m2.group(1))

    return sorted(curves, key=str.lower)

def _extract_protocol_versions(text: str) -> List[str]:
    """Extrae versiones de protocolo TLS soportadas."""
    t = _clean_ansi(text)
    block_re = re.compile(r'#\s*Supported\s*Protocol\s*Versions.*?(?:\n#|\Z)', 
                         re.IGNORECASE | re.DOTALL)
    m = block_re.search(t)
    vers = []
    if m:
        block = m.group(0)
        for ln in block.splitlines():
            ln = ln.strip()
            m_item = re.search(r'\d+\.\s*(TLS\s*1\.[23])', ln, re.IGNORECASE)
            if m_item:
                vers.append(m_item.group(1).upper().replace(" ", ""))
    return sorted(set(vers))

def _extract_ciphers_by_version(text: str) -> Dict[str, List[str]]:
    """Extrace cifrados por versión TLS."""
    t = _clean_ansi(text)
    out = {"TLS1.2": [], "TLS1.3": []}
    block_re = re.compile(r'#\s*Supported\s*Cipher\s*Suites.*?(?:\n#|\Z)', 
                         re.IGNORECASE | re.DOTALL)
    m = block_re.search(t)
    if not m:
        return out
    
    block = m.group(0)
    cur = None
    for ln in block.splitlines():
        s = ln.strip()
        if re.search(r'^##\s*TLS\s*1\.2', s, re.IGNORECASE):
            cur = "TLS1.2"
            continue
        if re.search(r'^##\s*TLS\s*1\.3', s, re.IGNORECASE):
            cur = "TLS1.3"
            continue
        if cur and re.search(r'^\d+\.\s+', s):
            name = re.sub(r'^\d+\.\s+', "", s)
            name = re.sub(r'\s*\(.*\)\s*$', "", name).strip()
            if name:
                out[cur].append(name)
    
    out["TLS1.2"] = sorted(set(out["TLS1.2"]))
    out["TLS1.3"] = sorted(set(out["TLS1.3"]))
    return out

def _extract_supported_signature_algs(text: str) -> List[str]:
    """Extrae algoritmos de firma soportados."""
    sigs = set()
    block_re = re.compile(r'#\s*Supported\s*Signature\s*Algorithms.*?(?:\n#|\Z)', 
                         flags=re.IGNORECASE | re.DOTALL)
    m = block_re.search(_clean_ansi(text))
    block = m.group(0) if m else ""

    if block:
        for line in block.splitlines():
            ln = line.strip().lower()
            if any(k in ln for k in ("rsa", "ecdsa", "dilithium", "falcon", "sphincs")):
                algo = re.sub(r'^[\*\-\d\.\s]+', "", ln)
                if algo:
                    sigs.add(algo.upper())

    return sorted(sigs)

def _extract_cert_algs(text: str) -> List[str]:
    """Extrae algoritmos de certificado."""
    algs = set()
    for m in re.finditer(
        r'^\s*\*\s*Algorithm:\s*([A-Za-z0-9\+\-_/]+)\s$|^\s*\*\s*Algorithm:\s*([A-Za-z0-9\+\-_/]+)$',
        _clean_ansi(text), flags=re.IGNORECASE | re.MULTILINE):
        alg = (m.group(1) or m.group(2))
        if alg:
            algs.add(alg.upper())
    return sorted(algs)

def _extract_alpns(text: str) -> List[str]:
    """Extrace protocolos ALPN soportados."""
    t = _clean_ansi(text)
    block_re = re.compile(r'#\s*Supported\s*Extensions.*?(?:\n#|\Z)', 
                         re.IGNORECASE | re.DOTALL)
    m = block_re.search(t)
    if not m:
        return []
    
    block = m.group(0)
    sub = re.search(r'Application\s*Layer\s*Protocols\s*:\s*(.*?)(?:\n\S|\Z)', 
                   block, re.IGNORECASE | re.DOTALL)
    if not sub:
        return []
    
    items = []
    for ln in sub.group(1).splitlines():
        ln = ln.strip()
        m_item = re.search(r'^\d+\.\s*([A-Za-z0-9\-/\.]+)$', ln)
        if m_item:
            items.append(m_item.group(1))
    return sorted(set(items))

def _extract_sct_count(text: str) -> int:
    """Cuenta Signed Certificate Timestamps."""
    t = _clean_ansi(text)
    start = t.find("End Entity:")
    scope = t[start:] if start != -1 else t
    m = re.search(
        r'Signed Certificate Timestamps\s*:\s*(.*?)(?:\n\s*\d+\.\s*[A-Z].*?:|^\s*$|\Z)',
        scope, re.IGNORECASE | re.DOTALL | re.MULTILINE)
    if not m:
        return 0
    block = m.group(1)
    return len(re.findall(r'^\s*\d+\.\s*$|^\s*Version\s*:\s*V\d', 
                         block, re.IGNORECASE | re.MULTILINE))

def _extract_ocsp_status(text: str) -> Dict[str, str]:
    """Extrae estado OCSP."""
    t = _clean_ansi(text)
    m = re.search(
        r'Certificate\s*Status\s*:\s*(\w+)(?:.*?\n\s*\*\s*Produced At\s*:\s*([^\n]+))?(?:.*?\n\s*\*\s*Next Update\s*:\s*([^\n]+))?',
        t, re.IGNORECASE | re.DOTALL)
    if not m:
        return {}
    status = (m.group(1) or "").strip().lower()
    produced = (m.group(2) or "").strip()
    nextup = (m.group(3) or "").strip()
    return {"status": status, "produced_at": produced, "next_update": nextup}

def _extract_cert_validity(text: str) -> Dict[str, object]:
    """Extrae validez del certificado."""
    t = _clean_ansi(text)
    m = re.search(
        r'Validity\s*:\s*(?:.|\n)*?Not Before\s*:\s*([^\n]+)\n(?:.|\n)*?Not After\s*:\s*([^\n]+)\n(?:.|\n)*?Remaining\s*:\s*([0-9]+)',
        t, re.IGNORECASE)
    if not m:
        return {}
    nb, na, rem = m.group(1).strip(), m.group(2).strip(), int(m.group(3))
    return {"not_before": nb, "not_after": na, "remaining_days": rem}

def _extract_public_key_info(text: str) -> Dict[str, object]:
    """Extrae información de clave pública."""
    t = _clean_ansi(text)
    m = re.search(r'Public\s*Key\s*:\s*([A-Za-z0-9\-]+)\s*\((\d+)\s*bits\)', t, re.IGNORECASE)
    if not m:
        m2 = re.search(r'Public-?Key\s*:\s*\((\d+)\s*bit\)\s*\n\s*([A-Za-z0-9\-]+)', t, re.IGNORECASE)
        if m2:
            return {"key_type": m2.group(2).upper(), "key_size_bits": int(m2.group(1))}
        return {}
    return {"key_type": m.group(1).upper(), "key_size_bits": int(m.group(2))}

def _extract_leaf_signature_algo(text: str) -> str:
    """Extrae algoritmo de firma del leaf certificate."""
    t = _clean_ansi(text)
    scope = t.split("End Entity:", 1)[1] if "End Entity:" in t else t
    m = re.search(r'Signature\s*Algorithm\s*:\s*([^\n]+)', scope, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def parse_cryptolyze_output(file_path_or_text):
    """
    Parsea la salida de cryptolyze desde archivo o texto.
    Retorna diccionario con todos los artefactos extraídos.
    """
    # Determinar si es ruta de archivo o texto directo
    if os.path.exists(file_path_or_text):
        try:
            with open(file_path_or_text, "r", encoding="utf-8", errors="ignore") as fh:
                full_text = fh.read()
        except Exception as e:
            raise Exception(f"Error leyendo archivo {file_path_or_text}: {e}")
    else:
        # Asumir que es texto directo
        full_text = file_path_or_text
    
    # Limpiar ANSI del texto completo
    full_text_clean = _clean_ansi(full_text)
    
    # Extraer todo
    artifacts = {
        "raw_text": full_text,
        "clean_text": full_text_clean,
        "named_curves": _extract_named_curves(full_text_clean),
        "supported_signature_algorithms": _extract_supported_signature_algs(full_text_clean),
        "certificate_algorithms": _extract_cert_algs(full_text_clean),
        "issuer_cn": _extract_issuer_cn(full_text_clean),
        "subject_cn": _extract_subject_cn(full_text_clean),
        "protocol_versions": _extract_protocol_versions(full_text_clean),
        "ciphers_by_version": _extract_ciphers_by_version(full_text_clean),
        "alpns": _extract_alpns(full_text_clean),
        "sct_count": _extract_sct_count(full_text_clean),
        "ocsp_status": _extract_ocsp_status(full_text_clean),
        "certificate_validity": _extract_cert_validity(full_text_clean),
        "public_key_info": _extract_public_key_info(full_text_clean),
        "leaf_signature_algorithm": _extract_leaf_signature_algo(full_text_clean)
    }
    
    return artifacts