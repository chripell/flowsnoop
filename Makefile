
all: flowsnoop

.PHONY: flowsnoop
flowsnoop: 
	go build ./...

.PHONY: flowsnoop
clean:
	rm -f flowsnoop
	find . -name '*~' -exec rm {} \;
