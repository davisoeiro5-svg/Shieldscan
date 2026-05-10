# 🛡️ ShieldScan — HTTP Security Analyzer

> Analise os headers de segurança HTTP de qualquer site em segundos. Descubra vulnerabilidades e saiba como corrigi-las.

![ShieldScan](https://img.shields.io/badge/ShieldScan-v1.0-00e5ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![Status](https://img.shields.io/badge/Status-Live-00ff88?style=for-the-badge)

---

## 🔍 O que é o ShieldScan?

O ShieldScan é uma ferramenta de análise de segurança web que verifica os **headers de segurança HTTP** de qualquer site publicamente acessível. Ele retorna uma nota de **A a D** e explica cada vulnerabilidade encontrada em português, com dicas de como corrigi-las.

🌐 **Acesse agora:** [davisoeiro5-svg.github.io/Shieldscan](https://davisoeiro5-svg.github.io/Shieldscan)

---

## 🛠️ Headers analisados

| Header | Proteção |
|--------|----------|
| `Content-Security-Policy` | Ataques XSS (Cross-Site Scripting) |
| `Strict-Transport-Security` | Downgrade de HTTPS para HTTP |
| `X-Frame-Options` | Clickjacking via iframes |
| `X-Content-Type-Options` | MIME Sniffing |
| `Referrer-Policy` | Vazamento de dados via URL |
| `Permissions-Policy` | Acesso indevido a câmera, microfone e GPS |

---

## ⚙️ Tecnologias utilizadas

**Backend**
- Python 3
- Flask — servidor web
- Flask-CORS — comunicação entre frontend e backend
- Requests — requisições HTTP

**Frontend**
- HTML5, CSS3, JavaScript puro
- Design responsivo com tema cybersecurity

**Deploy**
- Backend → [Render](https://render.com)
- Frontend → [GitHub Pages](https://pages.github.com)
- Monitoramento → [UptimeRobot](https://uptimerobot.com)

---

## 🔒 Segurança da própria ferramenta

O ShieldScan foi desenvolvido com boas práticas de segurança:

- **Proteção contra SSRF** — bloqueia requisições para IPs privados (`127.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8`, `169.254.0.0/16` e outros)
- **Rate Limiting** — máximo de 10 requisições por minuto por IP
- **Validação de URL** — rejeita entradas malformadas antes de processar
- **Timeout** — requisições limitadas a 8 segundos

---

## 🚀 Como rodar localmente

**1. Clone o repositório**
```bash
git clone https://github.com/davisoeiro5-svg/Shieldscan.git
cd Shieldscan
```

**2. Instale as dependências**
```bash
pip install -r requirements.txt
```

**3. Inicie o backend**
```bash
python app.py
```

**4. Abra o frontend**

Abra o arquivo `index.html` no navegador ou use a extensão Live Server do VS Code.

---

## 📊 Exemplos de resultados

| Site | Nota | Observação |
|------|------|------------|
| youtube.com | A | 1 header ausente |
| github.com | A | Configuração excelente |
| Sites de pequenas empresas | C/D | Configuração básica ou ausente |

---

## 📌 Limitações conhecidas

- Analisa apenas headers HTTP — sites que implementam segurança via meta tags ou JavaScript podem aparecer com headers ausentes mesmo estando protegidos
- O plano gratuito do Render pode ter delay de até 50s na primeira requisição após inatividade

---

## 👨‍💻 Autor

**Davi Soeiro**
Estudante de Análise e Desenvolvimento de Sistemas

[![LinkedIn](https://img.shields.io/badge/LinkedIn-David%20Pimentel-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/david-pimentel-soeiro-modesto-62b775299)
[![GitHub](https://img.shields.io/badge/GitHub-davisoeiro5--svg-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/davisoeiro5-svg)

---

## 📄 Licença

Este projeto está sob a licença MIT — sinta-se à vontade para usar, estudar e contribuir.

---

<p align="center">Feito com 🛡️ e muito aprendizado</p>
