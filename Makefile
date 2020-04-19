
all: flowsnoop

flowsnoop: flowsnoop.go
	go build flowsnoop.go

clean:
	rm -f flowsnoop *~
