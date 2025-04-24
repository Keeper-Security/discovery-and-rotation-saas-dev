# Dockerized Plugin CLI 

## Build

From the project use the following command to build the Docker image.

```shell
docker build -f docker/Dockerfile -t plugin_test .
```

## Alias

```shell
alias plugin_test='docker run --rm -it --workdir /wd -v $PWD:/wd plugin_test plugin_test'
```

## Running

