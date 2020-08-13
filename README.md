![Build Website](https://github.com/aquasecurity/avd-generator/workflows/Build%20Website/badge.svg)
# AVD Generator 

### Description
This is the page generator component of AVD

### Generated Website
https://github.com/aquasecurity/avd

### Building
Note: Set `baseURL="/"` [here](https://github.com/aquasecurity/avd-generator/blob/master/config.toml#L1-L4) before proceeding.

#### tl;dr    
`make md-clean md-build sync-all md-generate hugo-generate nginx-restart`    
then navigate to `http://localhost:9011` to view the pages.

#### To just build markdown pages:
`make md-generate` markdowns will be generated in `avd-repo/content/`

#### To just build the hugo site:
`make hugo-generate` site will be generated in `avd-repo/docs/`

#### To have a functional search:
1. Run MeiliSearch locally      
`docker run -p 7700:7700 -v $(pwd)/data.ms:/data.ms getmeili/meilisearch`

2. Setup search index    
`curl -X POST 'http://127.0.0.1:7700/indexes' --data '{ "uid" : "content", "primaryKey": "title"}'`  
   
3. Add generated index.json to build search indexes    
`curl -X POST 'http://127.0.0.1:7700/indexes/content/documents' --data @docs/index.json`  
 
4. To monitor index build progress:    
`curl -X GET 'http://localhost:7700/indexes/content/updates'`

5. Set the host and apiKey in `static/js/fastsearch.js` for using MeiliSearch:   
``` 
meilisearch = new MeiliSearch({
         host: 'http://localhost',
         apiKey: "<public meilisearch if you set a master key only, otherwise remove>",
 })
```
