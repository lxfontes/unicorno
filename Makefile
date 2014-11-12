dev:
	go build -o unicorno

deps:
	go get -d

linux:
	GOARCH=amd64 GOOS=linux go build -o unicorno

clean:
	go clean
