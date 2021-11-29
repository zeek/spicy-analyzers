FROM zeekurity/zeek-dev

# ADD https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_debian11/packages/spicy-dev.deb /tmp
ADD https://github.com/zeek/spicy/releases/download/v1.3.0/spicy_linux_debian11.deb /tmp
RUN dpkg -i /tmp/spicy_linux_debian11.deb
ENV PATH /opt/spicy/bin:$PATH

# Install dependencies for Spicy JIT, building against Zeek and package building.
RUN apt-get update \
 && apt-get install --no-install-recommends -y g++ gcc libpcap0.8-dev cmake make \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Enable loading of plugins installed with zkg.
RUN echo '@load packages' >> $(zeek-config --site_dir)/local.zeek
