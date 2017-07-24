FROM golang:latest
RUN mkdir -p /go/src/github.com/loganmhb/ktcoin
ADD . /go/src/github.com/loganmhb/ktcoin
WORKDIR /go/src/github.com/loganmhb/ktcoin
ENV GOPATH "/go"
CMD go run main.go
