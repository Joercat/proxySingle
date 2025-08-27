# Stage 1: Build environment
FROM ubuntu:22.04 AS build

# Set a non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install core build tools and libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libboost-dev \
    libssl-dev \
    libgumbo-dev \
    libz-dev \
    libbrotli-dev \
    libsqlite3-dev \
    pkg-config \
    ca-certificates

# Clone and build vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git /vcpkg
WORKDIR /vcpkg
RUN ./bootstrap-vcpkg.sh

# Install spdlog using vcpkg
RUN ./vcpkg install spdlog --triplet x64-linux

# Set the working directory for the source code
WORKDIR /app

# Copy the source files
COPY proxy.cpp CMakeLists.txt ./

# Configure and build the project with CMake
RUN cmake -DCMAKE_TOOLCHAIN_FILE=/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release .
RUN cmake --build .

# Stage 2: Final image
FROM ubuntu:22.04 AS final

# Install runtime dependencies without version numbers
RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    libgumbo2 \
    libz-dev \
    libbrotli-dev \
    libstdc++6 \
    ca-certificates

# Copy the compiled executable from the build stage
COPY --from=build /app/CPPProxy /usr/local/bin/CPPProxy

# The SQLite database is created at runtime, so we don't copy it.

# Set the command to run the application
CMD ["/usr/local/bin/CPPProxy"]
