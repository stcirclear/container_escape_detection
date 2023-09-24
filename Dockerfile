FROM ubuntu:22.04 as builder
LABEL maintainer="Shuo Li, Zixin Yuan"
LABEL Description="Image for building and testing container escape detection"

ARG DEBIAN_FRONTEND="noninteractive"
# ENV docker /docker

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt-get update && \
	apt-get install --no-install-recommends -y git vim clang cmake build-essential \
		g++ git zlib1g-dev llvm python3 python3-pip iproute2 libelf-dev \
		libdw-dev libpcre3-dev curl wget sudo libexpat1-dev libbpf-dev gcc-multilib \
		linux-tools-generic linux-tools-common
		#  linux-headers-$(uname -r) linux-tools-$(uname -r)
#RUN curl -fsSL https://get.docker.com | bash -s docker

FROM builder AS build
WORKDIR /container_monitor
COPY . /container_monitor
RUN make -C src/ opensnoop && cp /container_monitor/src/opensnoop /container_monitor/opensnoop && cp /container_monitor/src/dockerpsns.sh /container_monitor/dockerpsns.sh
RUN wget https://download.docker.com/linux/static/stable/x86_64/docker-17.03.0-ce.tgz \
	&& tar xf ./docker-17.03.0-ce.tgz && cp ./docker/docker ../usr/local/bin/docker
	# && ln -s /docker docker

#FROM ubuntu:22.04
#RUN apt-get update && \
#	apt-get install --no-install-recommends -y sudo python3 python3-pip curl libelf-dev && apt-get clean && \
#	rm -rf /var/lib/apt/lists/

#COPY --from=build /container_monitor/src/opensnoop /opensnoop
#RUN sudo mount -t debugfs debugfs /sys/kernel/debug

ENTRYPOINT ["python3"]
