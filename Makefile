md-build:
	go build -o generator .

md-test:
	go test -v ./...

md-clean:
	rm -f ./generator
	#find content/nvd -name "*.md" | xargs rm

md-generate: md-clean md-build
	-git clone git@github.com:aquasecurity/appshield.git appshield-repo
	-git clone git@github.com:aquasecurity/vuln-list.git vuln-list
	./generator

nginx-start:
	-cd docs; nginx -p . -c ../nginx.conf

nginx-stop:
	-nginx -p . -s stop

nginx-restart:
	make nginx-stop nginx-start

hugo-devel:
	hugo server -D

hugo-clean:
	rm -rf docs

hugo-generate: hugo-clean
	hugo --minify --destination=docs
