from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
import socket
import ipaddress
import os
from collections import defaultdict
import time

app = Flask(__name__)
CORS(app)

# ─── Rate Limiting simples (em memória) ─────────────────────────────────────
RATE_LIMIT_MAX = 10
RATE_LIMIT_JANELA = 60

requisicoes_por_ip = defaultdict(list)

def verificar_rate_limit(ip: str) -> bool:
    agora = time.time()
    requisicoes_por_ip[ip] = [t for t in requisicoes_por_ip[ip] if agora - t < RATE_LIMIT_JANELA]
    if len(requisicoes_por_ip[ip]) >= RATE_LIMIT_MAX:
        return False
    requisicoes_por_ip[ip].append(agora)
    return True


# ─── Proteção contra SSRF ────────────────────────────────────────────────────
IPS_BLOQUEADOS = [
    ipaddress.ip_network("127.0.0.0/8"),      # localhost
    ipaddress.ip_network("10.0.0.0/8"),        # rede privada classe A
    ipaddress.ip_network("172.16.0.0/12"),     # rede privada classe B
    ipaddress.ip_network("192.168.0.0/16"),    # rede privada classe C
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),         # endereços inválidos
    ipaddress.ip_network("::1/128"),           # localhost IPv6
    ipaddress.ip_network("fc00::/7"),          # rede privada IPv6
]

def ip_e_seguro(hostname: str) -> tuple:
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for rede in IPS_BLOQUEADOS:
            if ip in rede:
                return False, f"Endereço IP bloqueado por segurança: {ip_str}"
        return True, ip_str
    except socket.gaierror:
        return False, "Não foi possível resolver o domínio."
    except ValueError:
        return False, "Endereço IP inválido."

def extrair_hostname(url: str) -> str:
    sem_esquema = url.replace("https://", "").replace("http://", "")
    return sem_esquema.split("/")[0].split("?")[0].split(":")[0]


# ─── Definição dos headers analisados ───────────────────────────────────────

HEADERS_INFO = {
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "desc": "Controla quais recursos o navegador pode carregar. Protege contra XSS.",
        "tip": "Adicione: Content-Security-Policy: default-src 'self'",
        "weight": 3
    },
    "strict-transport-security": {
        "label": "Strict-Transport-Security",
        "desc": "Força o uso de HTTPS, impedindo ataques de downgrade para HTTP.",
        "tip": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "weight": 2
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "desc": "Impede que o site seja carregado em iframes. Protege contra Clickjacking.",
        "tip": "Adicione: X-Frame-Options: DENY ou SAMEORIGIN",
        "weight": 2
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "desc": "Impede MIME sniffing, evitando execução de arquivos maliciosos.",
        "tip": "Adicione: X-Content-Type-Options: nosniff",
        "weight": 1
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "desc": "Controla quais informações de URL são enviadas a sites externos.",
        "tip": "Adicione: Referrer-Policy: strict-origin-when-cross-origin",
        "weight": 1
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "desc": "Controla acesso a câmera, microfone e geolocalização.",
        "tip": "Adicione: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "weight": 1
    }
}

# ─── Funções auxiliares ──────────────────────────────────────────────────────

def normalizar_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def calcular_score(resultados: dict) -> str:
    total = 0
    maximo = 0
    for key, r in resultados.items():
        peso = HEADERS_INFO[key]["weight"]
        maximo += peso
        if r["status"] == "pass":
            total += peso
    percentual = (total / maximo) * 100 if maximo > 0 else 0
    if percentual >= 85: return "A"
    elif percentual >= 65: return "B"
    elif percentual >= 40: return "C"
    else: return "D"

def analisar_headers(headers_recebidos: dict) -> dict:
    headers_lower = {k.lower(): v for k, v in headers_recebidos.items()}
    resultados = {}
    for key, info in HEADERS_INFO.items():
        if key in headers_lower:
            resultados[key] = {"status": "pass", "value": headers_lower[key], "label": info["label"], "desc": info["desc"], "tip": info["tip"]}
        else:
            resultados[key] = {"status": "fail", "value": None, "label": info["label"], "desc": info["desc"], "tip": info["tip"]}
    return resultados


# ─── Rotas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"status": "ShieldScan API online 🛡️"})


@app.route("/scan", methods=["POST"])
def scan():

    # 1. Rate limiting
    ip_cliente = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip_cliente = ip_cliente.split(",")[0].strip()

    if not verificar_rate_limit(ip_cliente):
        return jsonify({"erro": f"Limite de {RATE_LIMIT_MAX} requisições por minuto atingido. Aguarde um momento."}), 429

    # 2. Validar corpo
    dados = request.get_json()
    if not dados or "url" not in dados:
        return jsonify({"erro": "Nenhuma URL enviada."}), 400

    url = normalizar_url(dados["url"])

    # 3. Validar formato
    if not re.match(r"https?://[^\s/$.?#].[^\s]*", url):
        return jsonify({"erro": "URL inválida. Ex: exemplo.com"}), 400

    # 4. Proteção SSRF
    hostname = extrair_hostname(url)
    seguro, mensagem = ip_e_seguro(hostname)
    if not seguro:
        return jsonify({"erro": f"URL bloqueada por segurança: {mensagem}"}), 403

    # 5. Requisição
    try:
        resposta = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "ShieldScan/1.0 Security Analyzer"}
        )

        dominio = resposta.url.split("/")[2]
        resultados = analisar_headers(dict(resposta.headers))
        score = calcular_score(resultados)

        return jsonify({
            "url": dominio,
            "url_final": resposta.url,
            "status_code": resposta.status_code,
            "score": score,
            "resultados": resultados
        })

    except requests.exceptions.SSLError:
        return jsonify({"erro": "Erro de SSL. O site pode ter certificado inválido."}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"erro": "Não foi possível conectar ao site. Verifique a URL."}), 400
    except requests.exceptions.Timeout:
        return jsonify({"erro": "O site demorou demais para responder (timeout de 8s)."}), 408
    except Exception as e:
        return jsonify({"erro": f"Erro inesperado: {str(e)}"}), 500


# ─── Iniciar servidor ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🛡️  ShieldScan API rodando na porta {port}")
    app.run(host="0.0.0.0", port=port)
