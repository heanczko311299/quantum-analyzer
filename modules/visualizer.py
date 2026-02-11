# modules/visualizer.py
"""
Visualización de resultados en consola.
Tablas, colores, barras de progreso, etc.
"""
from typing import List, Dict, Tuple, Optional
from colorama import Fore, Style

try:
    from tabulate import tabulate
    _TABULATE = True
except ImportError:
    _TABULATE = False

def _sep(char: str = "━", width: int = 72) -> str:
    """Línea separadora."""
    return char * width

def _status_bar(pct: int, width: int = 36) -> str:
    """Barra de estado coloreada para el score PQC readiness."""
    pct = max(0, min(100, int(pct)))
    if width <= 0:
        width = 36
    filled = int((pct / 100.0) * width) if pct > 0 else 0
    empty = width - filled
    bar = "█" * filled + "░" * empty
    color = Fore.GREEN if pct >= 70 else (Fore.YELLOW if pct >= 40 else Fore.RED)
    return color + bar + Style.RESET_ALL + f" {pct}%"

def _print_table(rows: List[List[str]], headers: List[str], color=Fore.LIGHTWHITE_EX):
    """Tabla bonita con tabulate; fallback ASCII."""
    if not rows:
        print(color + "   —" + Style.RESET_ALL)
        return
    
    # Asegurar que todas las celdas sean strings
    rows = [[str(cell) if cell is not None else "—" for cell in row] for row in rows]
    headers = [str(h) if h is not None else "" for h in headers]
    
    if _TABULATE:
        try:
            table = tabulate(rows, headers=headers, tablefmt="grid", stralign="left")
            print(color + table + Style.RESET_ALL)
        except Exception:
            _print_table_fallback(rows, headers, color)
    else:
        _print_table_fallback(rows, headers, color)

def _print_table_fallback(rows: List[List[str]], headers: List[str], color):
    """Fallback para tablas ASCII cuando tabulate no está disponible."""
    if not rows:
        print(color + "   —" + Style.RESET_ALL)
        return
    
    # Calcular anchos de columna
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Crear separador
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    
    def fmt_row(cells):
        row_cells = []
        for i, cell in enumerate(cells):
            if i < len(col_widths):
                row_cells.append(str(cell).ljust(col_widths[i]))
            else:
                row_cells.append(str(cell))
        return "| " + " | ".join(row_cells) + " |"
    
    print(color + sep)
    print(color + fmt_row(headers))
    print(color + sep)
    for row in rows:
        print(color + fmt_row(row))
    print(color + sep + Style.RESET_ALL)

def _yesno(v: bool) -> str:
    """Formatea booleano como Sí/No con colores."""
    return (Fore.GREEN + "Sí" + Style.RESET_ALL) if v else (Fore.RED + "No" + Style.RESET_ALL)

def _short(text: Optional[str], limit: int = 120) -> str:
    """Acorta textos largos con elipsis."""
    if text is None:
        return "—"
    t = str(text).strip()
    if not t:
        return "—"
    return t if len(t) <= limit else t[:limit - 1] + "…"

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

def _risk_from_attack(component: str, observed: str, attack: str) -> str:
    """Determina nivel de riesgo basado en componente y ataque."""
    a = (attack or "").lower()
    if "shor" in a:
        return "ALTO"
    
    obs_u = (observed or "").upper()
    if "AES_128" in obs_u:
        return "MEDIO"
    if "AES_256" in obs_u:
        return "BAJO"
    if "CHACHA20" in obs_u:
        return "MEDIO-BAJO"
    
    return "MEDIO"

def _short_alg_from_observed(component: str, observed: str) -> str:
    """Extrae algoritmo corto del componente observado."""
    c = (component or "").lower()
    obs = (observed or "").upper()
    
    if "key exchange" in c:
        for k in ("X25519", "X448", "P-256", "SECP256R1", "SECP384R1", "P-384", "SECP521R1", "P-521"):
            if k in obs:
                return "X25519" if k in ("SECP256R1", "P-256") else (k if k in ("X25519", "X448") else k.replace("SECP", "P-"))
        return (obs.split(",")[0] if "," in obs else obs.split()[0]).strip()[:8] if obs else "—"
    
    if "firmas" in c:
        if "RSA" in obs:
            return "RSA"
        if "ECDSA" in obs:
            return "ECDSA"
        if "ED25519" in obs:
            return "Ed25519"
        return "SIG"
    
    if "cifrado simétrico" in c:
        if "AES_256" in obs:
            return "AES256"
        if "AES_128" in obs:
            return "AES128"
        if "CHACHA20" in obs:
            return "CHACHA20"
        return "SYM"
    
    return "—"

def _attack_compact_rows(attack_surface: List[dict]) -> Tuple[List[List[str]], List[str]]:
    """
    Devuelve filas compactas para tabla de ataque.
    Returns: (rows, mitigations)
    """
    rows = []
    mitigs = []

    kex_present = False
    sig_rsa_present = False
    sig_ecdsa_present = False
    sym_aes128_present = False
    sym_aes256_present = False
    sym_chacha_present = False

    for it in attack_surface or []:
        comp = it.get("component", "")
        obs = it.get("observed", "")
        atk = it.get("quantum_attack", "")

        alg = _short_alg_from_observed(comp, obs)
        atk_short = "Shor" if "shor" in atk.lower() else "Grover"
        risk = _risk_from_attack(comp, obs, atk)

        comp_c = comp
        if "Key Exchange" in comp:
            comp_c = "Key Exchange"
            kex_present = True
        elif "Firmas (RSA)" in comp:
            comp_c = "Firmas"
            sig_rsa_present = True
        elif "Firmas (ECDSA)" in comp:
            comp_c = "Firmas"
            sig_ecdsa_present = True
        elif "Cifrado simétrico" in comp:
            comp_c = "Cifrado simétrico"
            if "AES_128" in obs.upper():
                sym_aes128_present = True
            if "AES_256" in obs.upper():
                sym_aes256_present = True
            if "CHACHA20" in obs.upper():
                sym_chacha_present = True

        rows.append([comp_c, alg, atk_short, risk])

    # Generar mitigaciones basadas en lo detectado
    if kex_present:
        mitigs.append("- Key Exchange: implementar ML‑KEM‑768 híbrido (p. ej., X25519+ML‑KEM‑768).")
    if sig_rsa_present or sig_ecdsa_present:
        mitigs.append("- Firmas: planear transición a Dilithium/Falcon (o SPHINCS+) cuando el ecosistema TLS lo permita.")
    if sym_aes128_present:
        mitigs.append("- Simétrico: preferir AES‑256‑GCM sobre AES‑128‑GCM para ≥128 bits post‑cuánticos.")
    if sym_chacha_present:
        mitigs.append("- Simétrico: CHACHA20‑POLY1305 es aceptable (~128 bits efectivos); ofrecer también AES‑256‑GCM si aplica.")
    if sym_aes256_present and not sym_aes128_present and not sym_chacha_present:
        mitigs.append("- Simétrico: mantener preferencia por AES‑256‑GCM.")

    return rows, mitigs

def render_compact_report(artifacts: Dict, analysis: Dict, attack_surface: List[Dict]):
    """
    Renderiza el reporte completo en consola.
    """
    from modules.analyzer import compute_pqc_score
    
    line = _sep()
    
    # 1. MOTIVOS
    print(Fore.WHITE + Style.BRIGHT + f"\n ▸ Motivos:" + Style.RESET_ALL)
    for r in analysis.get("reasons", []):
        print(Fore.LIGHTWHITE_EX + f"   • {r}" + Style.RESET_ALL)
    
    # 2. TLS RESUMEN
    protocol_versions = artifacts.get("protocol_versions", [])
    ciphers = artifacts.get("ciphers_by_version", {})
    alpns = artifacts.get("alpns", [])
    
    tls_rows = [
        ["Versiones", ", ".join(protocol_versions) if protocol_versions else "—"],
        ["Cifrados TLS 1.3", _fmt_list(ciphers.get("TLS1.3", []), limit=4)],
        ["ALPN", ", ".join(alpns) if alpns else "—"],
    ]
    print(Fore.WHITE + Style.BRIGHT + "\n ▸ TLS (resumen):" + Style.RESET_ALL)
    _print_table(tls_rows, headers=["Métrica", "Valor"])
    
    # 3. CERTIFICADO RESUMEN
    subject_cn = artifacts.get("subject_cn", "")
    issuer_cn = artifacts.get("issuer_cn", "")
    leaf_sig_algo = artifacts.get("leaf_signature_algorithm", "")
    public_key = artifacts.get("public_key_info", {})
    cert_validity = artifacts.get("certificate_validity", {})
    sct_count = artifacts.get("sct_count", 0)
    ocsp = artifacts.get("ocsp_status", {})
    
    pk_str = f"{public_key.get('key_type', '—') or '—'} {public_key.get('key_size_bits', '') or ''}".strip()
    valid_str = "—"
    if cert_validity:
        nb = cert_validity.get("not_before", "—")
        na = cert_validity.get("not_after", "—")
        rd = cert_validity.get("remaining_days", "—")
        valid_str = f"{nb}  →  {na}  (restan {rd} días)"
    
    ocsp_str = "—"
    if ocsp:
        ocsp_str = f"{ocsp.get('status', '—')}"
        if ocsp.get("next_update"):
            ocsp_str += f" (next: {ocsp.get('next_update')})"
    
    cert_rows = [
        ["Subject CN", _short(subject_cn)],
        ["Issuer CN", _short(issuer_cn)],
        ["Firma (leaf)", _short(leaf_sig_algo or "—")],
        ["Clave pública", pk_str or "—"],
        ["Validez", _short(valid_str)],
        ["SCT", str(sct_count)],
        ["OCSP", _short(ocsp_str)],
    ]
    print(Fore.WHITE + Style.BRIGHT + "\n ▸ Certificado (resumen):" + Style.RESET_ALL)
    _print_table(cert_rows, headers=["Campo", "Valor"])
    
    # 4. SUPERFICIE DE ATAQUE
    compact_rows, mitigs = _attack_compact_rows(attack_surface)
    if compact_rows:
        print(Fore.WHITE + Style.BRIGHT + "\n ▸ Superficie de ataque (resumen):" + Style.RESET_ALL)
        _print_table(compact_rows, headers=["Componente", "Alg.", "Ataque", "Riesgo PQ"])
        if mitigs:
            print(Fore.WHITE + Style.BRIGHT + "\n Mitigación:" + Style.RESET_ALL)
            for m in mitigs:
                print(Fore.LIGHTWHITE_EX + f"   {m}" + Style.RESET_ALL)
    
    # 5. EVIDENCIA
    evidence = analysis.get("evidence", [])
    if evidence:
        ev_rows = [[e["source"], _short(e.get("snippet", "—"), 80)] for e in evidence]
        print(Fore.WHITE + Style.BRIGHT + "\n ▸ Evidencia:" + Style.RESET_ALL)
        _print_table(ev_rows, headers=["Fuente", "Snippet"])
    
    # 6. VEREDICTO + SCORE
    verdict = analysis.get("verdict", "UNKNOWN")
    level = analysis.get("level", "error")
    label = analysis.get("label", "")
    confidence = analysis.get("confidence", 0.0)
    
    color = Fore.GREEN if level == "success" else (Fore.YELLOW if level == "warning" else Fore.RED)
    verdict_block = f"{verdict}  " + Style.DIM + f"(label={label}, confianza={confidence})"
    
    print(Fore.RED + line + Style.RESET_ALL)
    print(color + Style.BRIGHT + f" ▶ Veredicto: " + verdict_block + Style.RESET_ALL)
    
    # Calcular score
    score_obj = compute_pqc_score(
        analysis.get("has_pqc_kem", False),
        analysis.get("has_pqc_sig", False),
        protocol_versions,
        ciphers,
        sct_count,
        ocsp,
        public_key
    )
    
    print(Fore.WHITE + Style.BRIGHT + "\n ▸ PQC readiness:" + Style.RESET_ALL)
    print("   " + _status_bar(score_obj['pqc_readiness'], width=36))
    if score_obj.get("explain"):
        print(Style.DIM + "   Detalle: " + ", ".join(score_obj["explain"]) + Style.RESET_ALL)
    
    # 7. WARNINGS
    sig_algs = artifacts.get("supported_signature_algorithms", [])
    cert_algs = artifacts.get("certificate_algorithms", [])
    
    if any("SHA1" in s.upper() for s in (sig_algs + cert_algs)):
        print(Fore.YELLOW + "[WARNING] Se observaron algoritmos con SHA‑1 en firmas soportadas/certificados." + Style.RESET_ALL)
    
    if cert_validity and cert_validity.get("remaining_days", 99999) < 30:
        print(Fore.YELLOW + f"[WARNING] Certificado por expirar en {cert_validity['remaining_days']} días." + Style.RESET_ALL)
    
    if not protocol_versions or "TLS1.3" not in protocol_versions:
        print(Fore.YELLOW + "[WARNING] TLS 1.3 no soportado - considere habilitarlo para mejor seguridad." + Style.RESET_ALL)
    
    # 8. FOOTER
    print(Fore.RED + line + "\n" + Style.RESET_ALL)