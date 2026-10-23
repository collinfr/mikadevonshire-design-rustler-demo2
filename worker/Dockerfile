FROM golang:1.24-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    DOTNET_ROOT=/usr/share/dotnet \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    PATH=/usr/share/dotnet:/usr/local/go/bin:${PATH}

# 1. Install base utilities, build toolchains, CLIs, and multi-language runtimes
# Supported languages: C/C++, C# / .NET, Go, Java, JavaScript/TypeScript, Kotlin, Python, Ruby, Rust, PHP
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    git \
    build-essential \
    cmake \
    clang \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    openjdk-17-jdk-headless \
    maven \
    gradle \
    kotlin \
    ruby \
    ruby-dev \
    bundler \
    rustc \
    cargo \
    php-cli \
    php-mbstring \
    php-xml \
    php-curl \
    php-zip \
    composer \
    libicu72 \
    ca-certificates \
    gnupg \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
 && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && mkdir -p -m 755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
 && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli gh nodejs \
 && npm install -g typescript tsx yarn pnpm \
 && curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0 --install-dir /usr/share/dotnet \
 && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
 && rm -rf /var/lib/apt/lists/* /root/.npm /tmp/*

# 2. Download and pre-bake the CodeMender (cm) CLI binary from Google Artifact Registry
RUN curl -L -o /tmp/cm-linux-amd64.zip \
    "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media" \
 && unzip -q /tmp/cm-linux-amd64.zip -d /tmp/cm-dist \
 && mv /tmp/cm-dist/cm /usr/local/bin/cm \
 && chmod 777 /usr/local/bin/cm \
 && rm -rf /tmp/cm-linux-amd64.zip /tmp/cm-dist

# 3. Copy and set executable entrypoint script and helper scripts
COPY entrypoint.sh /entrypoint.sh
COPY attach_artifacts.py /attach_artifacts.py
COPY create_issues.py /create_issues.py
COPY resolve_finding.py /resolve_finding.py
COPY create_pr.py /create_pr.py
COPY post_pr_comments.py /post_pr_comments.py
RUN chmod +x /entrypoint.sh /attach_artifacts.py /create_issues.py /resolve_finding.py /create_pr.py /post_pr_comments.py

# 4. Set working directory for scans
WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
