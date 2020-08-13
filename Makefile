md-build:
	go build -o generator .

md-test:
	go test -v ./...

md-clean:
	rm -f ./generator

clone-all:
	git clone --depth 1 git@github.com:aquasecurity/vuln-list.git avd-repo/vuln-list
	rsync -av ./ avd-repo/ --exclude=avd-repo --exclude=.git --exclude=content --exclude=docs --exclude=Makefile --exclude=goldens

md-generate: md-clean md-build
	cd avd-repo && ./generator

nginx-start:
	-cd avd-repo/docs && nginx -p . -c ../nginx.conf

nginx-stop:
	-nginx -p . -s stop

nginx-restart:
	make nginx-stop nginx-start

hugo-devel:
	cd avd-repo && hugo server -D

hugo-clean:
	cd avd-repo && rm -rf docs

hugo-generate: hugo-clean
	cd avd-repo && hugo --minify --destination=docs
