# GROUND CONTROL STATION CONTAINER
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apt-utils \
    curl \
    software-properties-common \
    ca-certificates \
    iproute2 \
    nano \
    net-tools \
    wpasupplicant \
    isc-dhcp-client \
    iputils-ping \
    python3 \
    python3-pip \
    wget \
    git \
    make \
    g++ \
    expect \
    libnl-3-dev \
    libnl-genl-3-dev \
    expect \
    && pip3 install future pymavlink MAVProxy mavsdk \
    && rm -rf /var/lib/apt/lists/*

COPY ground-control-station/conf/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf

COPY ground-control-station/stages/arm-and-takeoff.py /arm-and-takeoff.py
COPY ground-control-station/stages/autopilot-flight.py /autopilot-flight.py
COPY ground-control-station/stages/return-to-land.py /return-to-land.py
COPY ground-control-station/stages/post-flight-analysis.py /post-flight-analysis.py
COPY ground-control-station/missions /missions
COPY ground-control-station/init /init
RUN chmod +x /init

# 7) Create user and groups
RUN groupadd user \
 && useradd -ms /bin/bash user -g user \
 && usermod -a -G dialout user

# 8) Download QGroundControl
# Define environment variable for architecture
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        wget -P /home/user https://qgroundcontrol.s3-us-west-2.amazonaws.com/builds/master/QGroundControl-x86_64.AppImage \
        && mv /home/user/QGroundControl-x86_64.AppImage /home/user/QGroundControl.AppImage \
        && chmod +x /home/user/QGroundControl.AppImage \
        && chown -R user:user /home/user; \
    elif [ "$ARCH" = "aarch64" ]; then \
        wget -P /home/user https://qgroundcontrol.s3-us-west-2.amazonaws.com/builds/master/QGroundControl-aarch64.AppImage \
        && mv /home/user/QGroundControl-aarch64.AppImage /home/user/QGroundControl.AppImage \
        && chmod +x /home/user/QGroundControl.AppImage \
        && chown -R user:user /home/user; \
    else \
        echo "Unsupported architecture: $ARCH"; \
        exit 1; \
    fi

USER user
WORKDIR /home/user

# 9) Entry-point scripts
COPY --chown=user:user ./qgc/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN \
    mkdir /home/user/scripts \
    && ln -s /usr/local/bin/entrypoint.sh /home/user/scripts/entrypoint.sh

# 10) QGC config
COPY ./qgc/config /home/user/.config/QGroundControl.org

CMD echo "Ground Control Online..." && /usr/bin/expect /init

