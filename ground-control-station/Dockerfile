ARG BASEIMAGE=ubuntu
ARG BASETAG=22.04
FROM ${BASEIMAGE}:${BASETAG} AS stage_apt

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV \
    DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN \
    rm -rf /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache \
    && sed -i 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list \
    && apt-get update

RUN \
    apt install -y \
        ca-certificates \
        curl \
        software-properties-common \
        wget

RUN \
    add-apt-repository ppa:kisak/kisak-mesa -y

# ------------------------------------------------------------------------- #
# FINAL STAGE
# ------------------------------------------------------------------------- #
FROM ${BASEIMAGE}:${BASETAG} AS stage_final

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 1) Set up environment variables
ENV \
    DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    LANGUAGE=en_US:en

# 2) Adjust apt sources
RUN sed -i 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list

# 4) Upgrade environment, install locales, generate en_US.UTF-8
RUN \
    --mount=type=cache,target=/var/cache/apt,from=stage_apt,source=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt,from=stage_apt,source=/var/lib/apt \
    --mount=type=cache,target=/etc/apt/sources.list.d,from=stage_apt,source=/etc/apt/sources.list.d \
    apt-get update && apt-get upgrade -y && \
    apt-get install --no-install-recommends -y locales && \
    locale-gen en_US.UTF-8

# 5) Install ca-certificates 
RUN \
    --mount=type=cache,target=/var/cache/apt,from=stage_apt,source=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt,from=stage_apt,source=/var/lib/apt \
    --mount=type=cache,target=/etc/apt/sources.list.d,from=stage_apt,source=/etc/apt/sources.list.d \
    apt-get install --no-install-recommends -y ca-certificates

# 6) Install everything in aptDeps.txt
RUN \
    --mount=type=cache,target=/var/cache/apt,from=stage_apt,source=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt,from=stage_apt,source=/var/lib/apt \
    --mount=type=cache,target=/etc/apt/sources.list.d,from=stage_apt,source=/etc/apt/sources.list.d \
    apt-get install --no-install-recommends -y \
    fuse \
    gstreamer1.0-gl \
    gstreamer1.0-libav \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-ugly \
    libgl1-mesa-dri \
    libgl1-mesa-glx \
    libgstreamer-plugins-base1.0-dev \
    libqt5gui5 \
    libsdl2-dev \
    mesa-utils \
    wget \
    x-window-system \
    x11-xserver-utils \
    xvfb \
    && rm -rf /tmp/*

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
COPY --chown=user:user ./ground-control-station/launch_qgc.sh /usr/local/bin/launch_qgc.sh
RUN \
    mkdir /home/user/scripts \
    && ln -s /usr/local/bin/entrypoint.sh /home/user/scripts/entrypoint.sh

# 10) QGC config
COPY ./ground-control-station/conf/QGroundControl.ini /home/user/.config/QGroundControl.org

USER root

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apt-utils \
    curl \
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

CMD echo "Ground Control Online..." && /usr/bin/expect /init