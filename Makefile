md-update-deps:
	cd docGen && go get github.com/aquasecurity/defsec \
	&& go mod tidy

md-build: 
	cd docGen && go build -o ../generator .

md-test:
	cd docGen && go test -v ./...

md-clean:
	rm -f ./generator


md-clone-redhat-api:
	@DIR="avd-repo/vuln-list-redhat"; \
	git clone --no-checkout --depth=1 --filter=blob:none git@github.com:aquasecurity/vuln-list-redhat.git $$DIR; \
	git -C "$$DIR" sparse-checkout init --cone; \
	git -C "$$DIR" sparse-checkout set api; \
	git -C "$$DIR" read-tree -mu HEAD

md-clone-all: md-clone-redhat-api
	# git clone git@github.com:aquasecurity/avd.git avd-repo/
	git clone git@github.com:aquasecurity/vuln-list.git avd-repo/vuln-list
	git clone git@github.com:aquasecurity/vuln-list-nvd.git avd-repo/vuln-list-nvd
	git clone git@github.com:aquasecurity/chain-bench.git avd-repo/chain-bench-repo
	git clone git@github.com:aquasecurity/cloud-security-remediation-guides.git avd-repo/remediations-repo
	git clone git@github.com:aquasecurity/trivy-policies.git avd-repo/trivy-policies-repo
	git clone git@github.com:aquasecurity/cloudsploit.git avd-repo/cloudsploit-repo

update-redhat-api:
	git -C avd-repo/vuln-list-redhat fetch --depth=1
	git -C avd-repo/vuln-list-redhat reset --hard origin/main

update-all-repos: update-redhat-api
	cd avd-repo/vuln-list && git pull
	cd avd-repo/vuln-list-nvd && git pull
	cd avd-repo/chain-bench-repo && git pull
	cd avd-repo/remediations-repo && git pull
	cd avd-repo/trivy-policies-repo && git pull
	cd avd-repo/cloudsploit-repo && git pull

remove-all-repos:
	rm -rf avd-repo/vuln-list
	rm -rf avd-repo/vuln-list-nvd
	rm -rf avd-repo/vuln-list-redhat
	rm -rf avd-repo/chain-bench-repo
	rm -rf avd-repo/trivy-policies-repo
	rm -rf avd-repo/cloudsploit-repo

sync-all:
	rsync -av ./ avd-repo/ --exclude=.idea --exclude=go.mod --exclude=go.sum --exclude=nginx.conf --exclude=main.go --exclude=main_test.go --exclude=README.md --exclude=avd-repo --exclude=.git --exclude=.gitignore --exclude=.github --exclude=content --exclude=docs --exclude=Makefile --exclude=goldens

md-generate:
	cd avd-repo && ./generator

nginx-start:
	-cd avd-repo/docs && nginx -p . -c ../../nginx.conf

nginx-stop:
	@if pgrep nginx > /dev/null; then \
		cd avd-repo/docs && nginx -s stop -p . -c ../../nginx.conf; \
	else \
		echo "Nginx is not running."; \
	fi

nginx-restart:
	make nginx-stop nginx-start

hugo-devel:
	hugo server -D --debug

hugo-clean:
	cd avd-repo && rm -rf docs

hugo-generate: hugo-clean
	cd avd-repo && ./ci/nvd_pages_build.sh
	echo "avd.aquasec.com" > avd-repo/docs/CNAME

simple-host:
	cd avd-repo/docs && python3 -m http.server

copy-assets:
	cp -R avd-repo/remediations-repo/resources avd-repo/docs/resources
	touch avd-repo/docs/.nojekyll

build-all-no-clone: md-clean md-build sync-all md-generate hugo-generate copy-assets nginx-restart
	echo "Build Done, navigate to http://localhost:9011/ to browse"

build-all: md-clean md-build md-clone-all sync-all md-generate hugo-generate copy-assets nginx-restart
	echo "Build Done, navigate to http://localhost:9011/ to browse"

compile-theme-sass:
	cd themes/aquablank/static/sass && sass avdblank.scss:../css/avdblank.css && sass avdblank.scss:../css/avdblank.min.css --style compressed