I was having issues with the version of lief package in Ubuntu 22.04.2 so I updated it using poetry.

My replica of the help: 


## From source

1.  Install [Git](https://git-scm.com/download/) if you don't have it yet.
2.  Install the [Poetry](https://python-poetry.org/docs/#installation) Python package manager.
3.  **Clone** the unblob **repository from GitHub**:

        git clone https://github.com/onekey-sec/unblob.git

4.  Install **Python dependencies** with Poetry:

    1.  Python packages:

            cd unblob
            poetry add lief==0.13.2
            poetry install --no-dev

    2.  Make sure you [installed all extractors](#install-extractors).

    3.  Check that everything works correctly:

            poetry run unblob --show-external-dependencies
          
## Install extractors

There is a handy `install-deps.sh` script included in the repository and PyPI packages that can be used to install the following dependencies.

1.  With your operating system package manager:  
    On Ubuntu 22.04.2, install extractors with APT:

        sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd lz4

2.  If you need **squashfs support**, install sasquatch:

        curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_amd64.deb
        sudo dpkg -i sasquatch_1.0_amd64.deb
        rm sasquatch_1.0_amd64.deb

3. If you need **squashfs support**, install sasquatch(arm64):
        curl -L -o sasquatch_1.0_arm64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_arm64.deb
        sudo dpkg -i sasquatch_1.0_arm64.deb
        rm sasquatch_1.0_arm64.deb
