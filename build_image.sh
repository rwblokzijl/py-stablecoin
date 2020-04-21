#!/bin/bash

if [[ $1 == "clean" ]]; then
    rm requirements.txt
    exit
fi

if [[ $1 == "full" ]]; then
    pipenv lock -r > requirements.txt
fi

docker build -t stablecoin .

