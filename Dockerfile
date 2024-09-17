FROM golang:1.23.1

RUN apt-get update

COPY . /root/idash2024
