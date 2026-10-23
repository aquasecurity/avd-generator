![Build Website](https://github.com/aquasecurity/avd-generator/workflows/Build%20Website/badge.svg)
# AVD Generator

### Description
This is the page generator component of AVD

### Generated Website
https://github.com/aquasecurity/avd

### Building
Note: Set `baseURL="/"` [here](https://github.com/aquasecurity/avd-generator/blob/main/config.toml#L1-L4) before proceeding.

#### tl;dr for just the UI
`make hugo-devel` and then navigate to `http://localhost:1313` to view the site.

#### Cryptographic rule documentation

The pages in `content/crypto/` are maintained as Markdown rather than generated from another repository. Keep their rule IDs, titles, severities, and detection conditions consistent with [Trivy's built-in crypto rules](https://github.com/aquasecurity/trivy/blob/3a0164d6cd627645220730d48d51dc71e10e7156/pkg/crypto/check/rules.go).

Run `make hugo-devel` to preview these pages at `http://localhost:1313/crypto/` without downloading the vulnerability or policy repositories. The other sections require the full build described below. The search box uses the deployed MeiliSearch index, so unpublished pages will not appear in search results. Hugo still generates their entries in the local `searchindex.json`.

The Hugo pull request workflow builds the authored pages and makes the generated site available as the `avd-preview` artifact. To view a downloaded artifact, extract it, run `python3 -m http.server 9011` in that directory, and open `http://localhost:9011/crypto/`.

#### tl;dr for the full build with real content
`make md-clean md-build sync-all md-generate hugo-generate serve`
then navigate to `http://localhost:9011` to view the pages.

If changes are made to the existing AVD page structure (removal of existing fields), the following must be done:
1. AVD content must be regenerated (`rm -rf content/nvd && mkdir -p content/nvd`)
2. Build must be done manually and pushed up to AVD repo (not through GitHub Actions)
This is needed to avoid tripping the Aqua Custom content logic.

#### To just build markdown pages:
`make md-generate` markdowns will be generated in `avd-repo/content/`

#### To just build the hugo site:
`make hugo-generate` site will be generated in `avd-repo/docs/`

#### To have a functional search:
1. Run MeiliSearch locally
`docker run -p 7700:7700 -v $(pwd)/data.ms:/data.ms getmeili/meilisearch`

2. Setup search index
`curl -X POST 'http://127.0.0.1:7700/indexes' -H 'Content-Type: application/json' --data '{ "uid" : "avd", "primaryKey": "title"}'`

3. Add generated index.json to build search indexes
`curl -X POST 'http://127.0.0.1:7700/indexes/avd/documents' --data @docs/index.json`

4. To monitor index build progress:
`curl -X GET 'http://localhost:7700/indexes/avd/updates'`

5. Set the host and apiKey in `static/js/fastsearch.js` for using MeiliSearch:
```
meilisearch = new MeiliSearch({
         host: 'http://localhost',
         apiKey: "<public meilisearch if you set a master key only, otherwise remove>",
 })
```
