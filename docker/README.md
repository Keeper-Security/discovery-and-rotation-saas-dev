# Dockerized Plugin CLI 

## Build

From the project directory, use the following command to build the Docker image.
Must be run from the project directory in order to include the Python modules.

```shell
docker build -f docker/Dockerfile -t plugin_test .
```

## Alias

And alias can be added to you `.bashrc`, `.zsh`, or equivalent startup shell script.
It can also be set per shell environment.

```shell
alias plugin_test='docker run --rm -it --workdir /wd -v $PWD:/wd plugin_test plugin_test'
```

## Running

Without using an alias.

```shell
docker run --rm -it --workdir /wd -v $PWD:/wd plugin_test plugin_test -f PYTHON_FILE -u USER_RECORD_UID -c CONFIG_RECORD_UID
```

With an alias.

```shell
plugin_test -f PYTHON_FILE -u USER_RECORD_UID -c CONFIG_RECORD_UID
```

