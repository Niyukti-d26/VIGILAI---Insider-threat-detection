FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    gcc \
    g++ \
    build-essential \
    python3-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs from source to support Kyber/Dilithium
WORKDIR /oqs
RUN git clone https://github.com/open-quantum-safe/liboqs . && \
    mkdir build && cd build && \
    cmake -GNinja .. && \
    ninja && \
    ninja install

ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
