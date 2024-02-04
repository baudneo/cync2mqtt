FROM alpine:3.18.2 as base

ARG MESH_CONFIG='/home/cync2mqtt/cync_mesh.yaml'
ARG CYNC_LIB_SRC='git+https://github.com/baudneo/cync2mqtt.git@baudneo-patch-1'

ENV MESH_CONFIG=${MESH_CONFIG}
ENV CYNC_LIB_SRC=${CYNC_LIB_SRC}
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBUG=0
RUN \
    mkdir -p home/cync2mqtt \
    && apk update \
    && apk add --no-cache \
      python3 \
      py3-pip \
      py3-requests \
      py3-yaml \
      py3-pycryptodome \
      py3-dbus \
      py3-docopt \
      py3-six py3-six-pyc \
      py3-passlib py3-passlib-pyc \
      py3-websockets py3-websockets-pyc \
      py3-pydbus py3-pydbus-pyc \
      \
      git \
      bluez \
      \
      build-base \
      glib-dev \
      \
      tree \
      nano \
    && echo "[install]" >> /etc/pip.conf \
    && echo "compile = no" >> /etc/pip.conf \
    && echo "[global]" >> /etc/pip.conf \
    && echo "no-cache-dir = True" >> /etc/pip.conf \
    && pip install amqtt@git+https://github.com/Yakifo/amqtt.git \
    "${CYNC_LIB_SRC}" \
    && apk del \
      build-base \
      glib-dev \
      git \
    && rm -rf /var/cache/apk/*

ENTRYPOINT ["cync2mqtt", "${MESH_CONFIG:-/home/cync2mqtt/cync_mesh.yaml}"]

