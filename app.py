from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "wallet", "bonus", "free", "gift", "payment", "bank",
    "signin", "confirm", "support", "unlock", "подарок", "вход",
    "подтвердить", "аккаунт", "пароль", "банк", "доставка"
}

def inspect_url(raw_url):
    """A transparent educational heuristic check; it does not visit the website."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return {"error": "Введите адрес сайта, например https://example.com"}

    candidate = raw_url if "://" in raw_url else "https://" + raw_url
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        if not host or "." not in host:
            return {"error": "Не удалось распознать домен. Проверьте адрес и попробуйте ещё раз."}
    except Exception:
        return {"error": "Адрес выглядит некорректно. Проверьте написание."}

    score = 0
    checks = []
    def add(title, detail, points=0, status="info"):
        nonlocal score
        score += points
        checks.append({"title": title, "detail": detail, "status": status, "points": points})

    scheme = parsed.scheme.lower()
    if scheme == "https":
        add("HTTPS", "Соединение использует HTTPS. Это защищает передачу данных, но не доказывает честность сайта.", 0, "good")
    else:
        add("Нет HTTPS", "Адрес не использует HTTPS. Не вводите на таком сайте пароли и платёжные данные.", 2, "warn")

    if "@" in parsed.netloc:
        add("Символ @ в адресе", "Может маскировать настоящий адрес узла и требует особого внимания.", 3, "bad")
    else:
        add("Структура адреса", "Символ @ в имени узла не обнаружен.", 0, "good")

    try:
        ipaddress.ip_address(host)
        add("IP-адрес вместо домена", "Сайт открыт по числовому IP-адресу. Это не всегда опасно, но часто требует проверки.", 2, "warn")
    except ValueError:
        add("Имя домена", "В адресе используется доменное имя.", 0, "good")

    if host.lower().startswith("xn--") or ".xn--" in host.lower():
        add("Punycode", "Обнаружен домен в формате Punycode: похожие символы разных алфавитов могут вводить в заблуждение.", 3, "bad")
    else:
        add("Похожие символы", "Явный префикс Punycode не обнаружен. Это не исключает подмену похожими символами.", 0, "info")

    labels = host.split(".")
    if len(labels) >= 5:
        add("Много поддоменов", f"В имени найдено {len(labels)} частей, разделённых точками. Проверьте, какой домен является основным.", 2, "warn")
    else:
        add("Поддомены", f"Количество частей домена: {len(labels)}.", 0, "good")

    if len(raw_url) > 100:
        add("Длинный URL", f"Адрес содержит {len(raw_url)} символов. Длинные ссылки могут скрывать важные детали.", 1, "warn")
    else:
        add("Длина адреса", f"Длина адреса — {len(raw_url)} символов.", 0, "good")

    if parsed.port and parsed.port not in (80, 443):
        add("Необычный порт", f"Указан порт {parsed.port}. Если вы не ожидали этого, проверьте источник ссылки.", 1, "warn")
    else:
        add("Порт", "Не обнаружен необычный номер порта.", 0, "good")

    text_to_scan = (host + " " + parsed.path + " " + parsed.query).lower()
    found = sorted({word for word in SUSPICIOUS_WORDS if word in text_to_scan})
    if found:
        add("Подозрительные слова", "Найдены слова: " + ", ".join(found) + ". Они могут встречаться и на легитимных сайтах.", min(2, len(found)), "warn")
    else:
        add("Ключевые слова", "Слова из простого списка подозрительных признаков не найдены.", 0, "good")

    if "-" in host:
        add("Дефисы в домене", "Дефис сам по себе не опасен, но в сочетании с другими признаками стоит проверить домен.", 1, "warn")
    else:
        add("Дефисы в домене", "Дефисов в имени домена нет.", 0, "good")

    score = min(score, 10)
    if score >= 6:
        level, label, summary, css = "high", "Высокий риск", "Обнаружено несколько настораживающих признаков. Не вводите личные данные, пока не проверите сайт.", "high"
    elif score >= 3:
        level, label, summary, css = "medium", "Нужна проверка", "Есть признаки, которые стоит проверить вручную. Оценка не доказывает, что сайт мошеннический.", "medium"
    else:
        level, label, summary, css = "low", "Мало явных признаков", "Простая проверка не нашла много тревожных сигналов. Это не гарантия безопасности сайта.", "low"

    return {
        "url": raw_url, "host": host, "score": score, "level": level,
        "label": label, "summary": summary, "css": css, "checks": checks,
        "disclaimer": "Это учебный прототип на основе правил, а не полноценная система кибербезопасности. Он не открывает сайт и не проверяет его репутацию."
    }

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        result = inspect_url(request.form.get("url", ""))
    return render_template("index.html", result=result)

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)
