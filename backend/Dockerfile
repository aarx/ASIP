FROM python:3.11

WORKDIR /app

# -----------------------------
# 1. System dependencies (stable)
# -----------------------------
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    dnsutils \
    nmap \
    golang \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# 2. Install recon tools (stable)
# -----------------------------
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/tomnomnom/assetfinder@latest

RUN wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip \
    && unzip findomain-linux.zip \
    && mv findomain /usr/local/bin/ \
    && chmod +x /usr/local/bin/findomain \
    && rm findomain-linux.zip

ENV PATH=$PATH:/root/go/bin

# -----------------------------
# 3. Python dependencies (semi-stable)
# -----------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install pyopenssl

# -----------------------------
# 4. Copy app (changes frequently)
# -----------------------------
COPY . .

# -----------------------------
# 5. Start app
# -----------------------------
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
