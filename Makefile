md-build:
	go build -o generator .

md-test:
	go test -v ./...

md-clean:
	rm -f ./generator

sync-all:
	rsync -av ./ avd-repo/ --exclude=go.mod --exclude=go.sum --exclude=nginx.conf --exclude=main.go --exclude=main_test.go --exclude=README.md --exclude=avd-repo --exclude=.git --exclude=.gitignore --exclude=.github --exclude=content --exclude=docs --exclude=Makefile --exclude=goldens

md-generate:
	cd avd-repo && ./generator

nginx-start:
	-cd avd-repo/docs && nginx -p . -c ../nginx.conf

nginx-stop:
	-nginx -p . -s stop

nginx-restart:
	make nginx-stop nginx-start

hugo-devel:
	hugo server -D

hugo-clean:
	cd avd-repo && rm -rf docs

hugo-generate: hugo-clean
	cd avd-repo && hugo --minify --destination=docs
