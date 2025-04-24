FROM alpine:3

RUN apk update \
    && apk add \
        gcc \
        g++ \
        libc-dev \
        linux-headers \
        python3 \
        python3-dev \
        py3-pip \
        libffi-dev

RUN pip install --upgrade --break-system-packages pip wheel

COPY kdnrm ./kdnrm
COPY plugin_dev ./plugin_dev
COPY setup.cfg .
COPY pyproject.toml .
COPY requirements.txt .

# Install the project
RUN pip install . --break-system-packages