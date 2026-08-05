FROM gcr.io/oss-fuzz-base/base-builder

RUN sed -i 's|http://|https://|g' /etc/apt/sources.list && \
    apt-get -o Acquire::Retries=8 -o Acquire::https::Timeout=60 update && \
    apt-get -o Acquire::Retries=8 -o Acquire::https::Timeout=60 \
      install -y --no-install-recommends \
      autoconf automake autopoint build-essential cups-common fontconfig \
      fonts-dejavu-core gettext git libavahi-client-dev libcap-dev \
      libcups2-dev libdbus-1-dev libexif-dev libfontconfig1-dev \
      libglib2.0-dev libjpeg-dev libgnutls28-dev liblcms2-dev libnss-mdns \
      libpng-dev libqpdf-dev libsystemd-dev libtiff-dev libtool \
      libwebp-dev libzstd-dev pkg-config patchelf poppler-utils zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/OpenPrinting/cups.git \
      $SRC/cups && \
    git clone --depth 1 https://github.com/OpenPrinting/cups-filters.git \
      $SRC/cups-filters && \
    git clone --depth 1 https://github.com/OpenPrinting/libcupsfilters.git \
      $SRC/libcupsfilters && \
    git clone --depth 1 https://github.com/OpenPrinting/libppd.git \
      $SRC/libppd && \
    git clone --depth 1 --recurse-submodules \
      https://github.com/michaelrsweet/pdfio.git $SRC/pdfio

COPY . $SRC/cupsfilters-core12
COPY build.sh $SRC/build.sh

WORKDIR $SRC/cups-filters
