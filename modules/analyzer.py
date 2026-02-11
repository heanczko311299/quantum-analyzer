# modules/analyzer.py
"""
Análisis de seguridad cuántica.
Detección de algoritmos PQC, evaluación de riesgos, scores.
"""
import re
from typing import List, Dict, Tuple, Optional

# Patrones de detección PQC
PQC_KEM_PATTERNS = [
    r"\bml[\s\-]?kem(?:[\s\-]?(?:512|768|1024))?\b",
    r"\bkyber(?:512|768|1024)?\b",
]

PQC_SIG_PATTERNS = [
    r"\bdilithium(?:2|3|5)?\b",
    r"\bfalcon(?:512|1024)?\b",
    r"\bsphincs[\+\-]?(?:128|192|256)?\b",
]

# Híbrido real = combinación clásica+PQC
PQC_HYBRID_COMBO = re.compile(
    r"(?i)\b(?:(x25519|x448|curve25519|prime256v1|secp256r1|secp384r1|secp521r1|p-256|p-384|p-521)"
    r"[\s_\-\+]*?(kyber(?:512|768|1024)?|ml[\s\-]?kem(?:[\s\-]?(512|768|1024))?))\b|"
    r"\b(?:(kyber(?:512|768|1024)?|ml[\s\-]?kem(?:[\s\-]?(512|768|1024))?)[\s_\-\+]*?"
    r"(x25519|x448|curve25519|prime256v1|secp256r1|secp384r1|secp521r1|p-256|p-384|p-521))\b"
)

def _has_pqc_in_groups(groups: List[str]) -> bool:
    """Verifica si hay KEM PQC en grupos TLS."""
    if not groups:
        return False
    g = " ".join(groups).lower()
    return bool(re.search(r'(kyber|mlkem|ml\-?kem)', g))

def _has_hybrid_combo(groups: List[str]) -> bool:
    """Verifica si hay combinación híbrida clásica+PQC."""
    if not groups:
        return False
    g = " ".join(groups)
    return bool(PQC_HYBRID_COMBO.search(g))

def _has_pqc_signature(sig_algs: List[str], cert_algs: List[str]) -> bool:
    """Verifica si hay firmas PQC."""
    combined = " ".join(sig_algs + cert_algs).lower()
    return any(re.search(p, combined) for p in PQC_SIG_PATTERNS)

def _fmt_list(items, limit=6):
    """Formatea lista para visualización compacta."""
    if not items:
        return "—"
    items = [str(i).strip() for i in items if str(i).strip()]
    if not items:
        return "—"
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", +{len(items)-limit} más"

def analyze_quantum_safety(artifacts: Dict) -> Dict:
    """
    Evalúa seguridad cuántica basada en artefactos extraídos.
    
    Returns:
        Dict con: verdict, level, reasons, label, confidence, explain,
                  evidence, has_pqc_kem, has_pqc_sig
    """
    groups: List[str] = artifacts.get("named_curves", []) or []
    sig_algs: List[str] = artifacts.get("supported_signature_algorithms", []) or []
    cert_algs: List[str] = artifacts.get("certificate_algorithms", []) or []
    issuer_cn: str = artifacts.get("issuer_cn", "") or ""
    
    has_pqc_kem = _has_pqc_in_groups(groups) or _has_hybrid_combo(groups)
    has_pqc_sig = _has_pqc_signature(sig_algs, cert_algs)
    
    # Determinar label y explicación
    if has_pqc_kem:
        label = "tls_pqc_hybrid"
        explain = "Se detectó KEM híbrido/PQC en los grupos soportados del handshake TLS."
    elif re.search(r'\bhybrid\b', issuer_cn, re.IGNORECASE):
        label = "tls_keyword_only"
        explain = "La palabra 'Hybrid' aparece en campos textuales del certificado."
    else:
        label = "none"
        explain = "No hay señales de 'hybrid' ni KEM PQC en TLS."
    
    # Calcular confianza
    confidence = 0.0
    if label == "tls_pqc_hybrid":
        confidence = 0.85 if has_pqc_sig else 0.8
    elif label == "tls_keyword_only":
        confidence = 0.45
    elif label == "none":
        confidence = 0.1
    
    confidence = round(max(0.0, min(1.0, confidence)), 2)
    
    # Determinar veredicto
    if has_pqc_kem and has_pqc_sig:
        verdict, level = "QUANTUM-SAFE", "success"
    elif has_pqc_kem:
        verdict, level = "HYBRID-READY", "warning"
    else:
        verdict, level = "NOT QUANTUM-SAFE", "error"
    
    # Razones principales
    reasons = []
    if has_pqc_kem: 
        reasons.append("Key Exchange PQC (Kyber/ML-KEM) detectado")
    if has_pqc_sig: 
        reasons.append("Firmas PQC (Dilithium/Falcon/SPHINCS+) detectadas")
    if not reasons: 
        reasons.append("No se detectó evidencia suficiente.")
    
    # Evidencia
    evidence = []
    if groups:
        evidence.append({"source": "tls.supported_groups", "snippet": ", ".join(groups[:8])})
    if issuer_cn:
        evidence.append({"source": "cert.issuer_cn", "snippet": issuer_cn})
    
    # Razones detalladas (para modo no-PQC)
    if not has_pqc_kem:
        reasons.append(f"No se detectó KEM PQC; grupos observados: {_fmt_list(groups)}")
        
        observed_sigs = sig_algs + cert_algs
        if observed_sigs:
            pretty = []
            for s in observed_sigs:
                token = s.split()[0].upper().replace("_", "-")
                pretty.append(token)
            reasons.append(f"No hay firmas PQC; firmas observadas: {_fmt_list(sorted(set(pretty)))}")
        else:
            reasons.append("No hay firmas PQC; no se pudieron extraer algoritmos de firma.")
    
    # TLS 1.3
    protocol_versions = artifacts.get("protocol_versions", [])
    has_tls13 = "TLS1.3" in protocol_versions
    reasons.append(f"TLS 1.3 soportado: {'sí' if has_tls13 else 'no'}")
    
    # Cifrados TLS 1.3
    ciphers = artifacts.get("ciphers_by_version", {})
    if ciphers and ciphers.get("TLS1.3"):
        reasons.append(f"Cifrados TLS 1.3 negociables: {_fmt_list(ciphers['TLS1.3'])}")
    
    return {
        "verdict": verdict,
        "level": level,
        "reasons": reasons,
        "label": label,
        "confidence": confidence,
        "explain": explain,
        "evidence": evidence,
        "has_pqc_kem": has_pqc_kem,
        "has_pqc_sig": has_pqc_sig,
        "protocol_versions": protocol_versions,
        "ciphers": ciphers,
        "issuer_cn": issuer_cn
    }

def build_attack_surface(groups: List[str], sig_algs: List[str],
                        cert_algs: List[str], ciphers_by_version: Dict[str, List[str]]) -> List[Dict]:
    """
    Construye superficie de ataque cuántico.
    
    Returns:
        Lista de items con: component, observed, quantum_attack, impact, recommendation
    """
    items = []
    groups_l = [g.lower() for g in (groups or [])]
    sig_tokens = (sig_algs or []) + (cert_algs or [])
    
    # Helper para crear items
    def mk_item(component, observed, attack, impact, recommendation):
        return {
            "component": component,
            "observed": observed,
            "quantum_attack": attack,
            "impact": impact,
            "recommendation": recommendation
        }
    
    # Detectar intercambio de claves vulnerable
    classic_curves = ["x25519", "prime256v1", "secp256r1", "secp384r1", 
                     "secp521r1", "curve25519", "x448", "p-256", "p-384", "p-521"]
    if any(g in groups_l for g in classic_curves):
        items.append(mk_item(
            component="Key Exchange (ECDH/ECDHE)",
            observed=", ".join(groups) if groups else "—",
            attack="Shor KEX",
            impact="Rompe el logaritmo discreto (ECC); compromete el secreto de sesión a largo plazo.",
            recommendation="Adoptar KEM híbrido PQC (p. ej., X25519+ML‑KEM‑768) o puro PQC cuando esté disponible."
        ))
    
    # Detectar firmas RSA
    if any("rsa" in t.lower() for t in sig_tokens):
        items.append(mk_item(
            component="Firmas (RSA)",
            observed="; ".join(sig_tokens[:6]) if sig_tokens else "RSA",
            attack="Shor Basic",
            impact="Rompe factorización (RSA); permite forjar firmas/identidades.",
            recommendation="Planear transición a firmas PQC (Dilithium/Falcon/SPHINCS+) cuando el ecosistema lo permita."
        ))
    
    # Detectar firmas ECDSA
    if any("ecdsa" in t.lower() for t in sig_tokens):
        items.append(mk_item(
            component="Firmas (ECDSA)",
            observed="; ".join(sig_tokens[:6]) if sig_tokens else "ECDSA",
            attack="Shor Complete",
            impact="Rompe logaritmo discreto en curvas elípticas; permite forjar firmas/identidades.",
            recommendation="Planear transición a firmas PQC (Dilithium/Falcon/SPHINCS+) cuando el ecosistema lo permita."
        ))
    
    # Analizar cifrados TLS 1.3
    c13 = (ciphers_by_version or {}).get("TLS1.3", []) or []
    c13u = [c.upper() for c in c13]
    
    if any("TLS_AES_128_GCM_SHA256" in c for c in c13u):
        items.append(mk_item(
            component="Cifrado simétrico (TLS 1.3)",
            observed="AES_128_GCM_SHA256",
            attack="Grover Complete",
            impact="Ventaja cuadrática contra búsqueda de clave; reduce margen de seguridad efectivo.",
            recommendation="Preferir AES-256-GCM (TLS_AES_256_GCM_SHA384) para mantener ≥128 bits post‑cuánticos."
        ))
    
    if any("TLS_CHACHA20_POLY1305_SHA256" in c for c in c13u):
        items.append(mk_item(
            component="Cifrado simétrico (TLS 1.3)",
            observed="CHACHA20_POLY1305_SHA256",
            attack="Grover Complete",
            impact="Clave de 256 bits mantiene ~128 bits efectivos frente a Grover.",
            recommendation="Aceptable; o bien ofrecer también AES‑256‑GCM para alinearse a guías corporativas."
        ))
    
    if any("TLS_AES_256_GCM_SHA384" in c for c in c13u):
        items.append(mk_item(
            component="Cifrado simétrico (TLS 1.3)",
            observed="AES_256_GCM_SHA384",
            attack="Grover Complete",
            impact="Parámetros robustos; margen ≥128 bits post‑cuánticos.",
            recommendation="Mantener preferencia por AES‑256‑GCM cuando sea posible."
        ))
    
    return items

def compute_pqc_score(has_pqc_kem: bool, has_pqc_sig: bool,
                     protocol_versions: List[str], ciphers: Dict[str, List[str]],
                     sct_count: int, ocsp: Dict[str, str], pubkey: Dict[str, object]) -> Dict:
    """Calcula score PQC readiness."""
    score = 0
    explain = []
    
    if has_pqc_kem: 
        score += 40
        explain.append("+40 KEM PQC/híbrido")
    if has_pqc_sig: 
        score += 20
        explain.append("+20 Firmas PQC")
    if "TLS1.3" in (protocol_versions or []): 
        score += 10
        explain.append("+10 TLS 1.3")
    
    c13 = [c.upper() for c in (ciphers or {}).get("TLS1.3", [])]
    if any("TLS_AES_256_GCM_SHA384" in c for c in c13): 
        score += 10
        explain.append("+10 AES-256-GCM")
    if any("TLS_CHACHA20_POLY1305_SHA256" in c for c in c13): 
        score += 5
        explain.append("+5 ChaCha20-Poly1305")
    
    if (sct_count or 0) >= 2: 
        score += 5
        explain.append("+5 SCT >= 2")
    if (ocsp or {}).get("status") == "good": 
        score += 5
        explain.append("+5 OCSP good")
    if (pubkey or {}).get("key_type") == "RSA" and (pubkey or {}).get("key_size_bits", 0) >= 3072: 
        score += 5
        explain.append("+5 RSA >= 3072 bits")
    
    return {"pqc_readiness": min(score, 100), "explain": explain}