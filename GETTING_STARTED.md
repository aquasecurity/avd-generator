# Getting Started

This guide seeks to provide you with a crash course to adding a new check type or make updates to existing checks.


There is the accompanying [PowerPoint](https://aquasecurity-my.sharepoint.com/:p:/g/personal/owen_rumney_aquasec_com/EX8RJOYqP1JKn-uDECphuLEBi_8Pougq9AH3JVFxPToQag?e=zJe43p) which is used in the video too.


## Local Development

> :rotating_light: PRs welcome, if you see a broken window, fix it! :tada:

Local development and running is generally very easy because Hugo is used to generate static web sites. 

To do anything, you need a populated `avd-repo` folder. If it doesn't already exist you can do 

```bash
make md-clone-all
```

If you have it already, do a
```bash
make update-all-repos
```

The general flow is this;

1. Parse the source repositories as per the specific requirements (eg Kube-Bench is json parsing, defsec is Go code, appshield is rego)

2. Generate Markdown from the source in the required hierarchical folder structure - generating menus to reflect hierarchy

3. Hugo Generates static content from markdown

### Prerequisites

1. You need [Hugo installed](https://gohugo.io/getting-started/installing/)

2. If you're doing anything with CSS, you need [sass installed](https://sass-lang.com/install)

### Adding New Data

How easy or hard adding a new source is largely dictated by the shape and structure of the data. For the most part, the steps are the same;

1. Add the source repo for download 
    1.1. Add to the [Makefile md-clone-all: and update-all-repos:](Makefile)
    1.2. Add a checkout section to the [cron.yml](.github/workflows/cron.yml) GitHub Action workflow
2. Add a code file in `docGen` for your new type of config to parse - this should generate a YAML file using Go Templating.
    2.1. Your generator is responsible for creating child menus - if you are going under compliance you will need to add nodes using the compliance menu generator

    In this example, a new entry is added to the `compliance` menu 
    ```go
	complianceMenu.AddNode(
        "cis-1.2.0", // MenuID - this is used as the URL portion, lowercase and URL safe
        "CIS 1.2.0", // Wherever there is a menu title, this will be used
        filepath.Join(outputDir), // the menu will create an _index.md file, in the dir you specify here
		"compliance", // the MenuID of the parent - top level are the only ones where this isn't used
        []string{}, // this is for remediation codes and isn't relevant here, its for defsec
        []menu.Breadcrumb{ //this is at the top breadcrumbs and provides links with his menu page as the last one
           {
                Name: "Compliance", // Pretty name for the parent menu item
                Url: "/compliance" // MenuID url
            }
        }, 
        "kubernetes", // this is the icon to be used should match something in themes/aquablank/static/images/icon_tile_XXXXXX.png - in this case icon_tile_kubernetes.png
        true // whether it is a tile based menu - all child items will be in tiles when try
    )
    ```

    2.2. The generator code should produce a markdown file with your content, the front matter in your document has required attributes.

    | Attribute | Purpose                                                                                          |
    |:----------|:-------------------------------------------------------------------------------------------------|
    | title     | The title shown in the menu and at the top of the page                                           |
    | id        | The ID of the check - be this an AVD or TRC ID or otherwise                                      |
    | source    | Where the AVD result will originate - defsec/appshield are Trivy for example                     |
    | icon      | icon - as found in themes/aquablank/static/images/icons_XXX_XXXXXXXX.png                         |
    | severity  | If severity isn't relevant, us "n/a"                                                             |
    | category  | Which top level it goes under. currently one of [misconfig, compliance, runtime, vulnerabilties] |


    2.3. An example template for Kube-Bench looks like this

    ```go
    title: {{.ShortName}}
    id: {{ .ID }}
    source: Kube Bench
    icon: kubernetes
    draft: false
    shortName: {{.ShortName}}
    severity: "n/a"
    version: {{ .Version}}
    category: compliance
    keywords: "{{ .Category }}"

    breadcrumbs: 
    - name: Compliance
        path: /compliance
    - name: {{ .NiceVersion }}
        path: /compliance/{{ .Version}}
    - name: {{ .ParentTitle }}
        path: /compliance/{{ .Version}}/{{ .Version}}-{{ .ParentID}}


    avd_page_type: avd_page

    ---

    ### {{ .ID }} {{ .ShortName }}
    {{ range .Checks }}
    #### {{ .ID }} {{ .Text}}

    ##### Recommended Action
    {{ .Remediation }}
    <br />

    {{ end }}
    ```

    2.4. The goal is to suck enough information out of you source data to produce a `map` of information to pass to the go template. For example, the required map for `Kube-Bench` is

    ```go
    map[string]interface{}{
		"ShortName":   checkGroup.Text,
		"ID":          checkGroup.ID,
		"Version":     config.Version,
		"NiceVersion": cisVersion(config.Version),
		"Category":    config.Type,
		"Checks":      checkGroup.Checks,
		"ParentID":    group,
		"ParentTitle": config.Text,
	}
    ```
   This has everything that is required to by used in the template execution.

   2.5. If your source data has a natural hierarchy, this is achieved by using file paths - nest the pages in the hierarchy in child directories for each section and use menus as above to achieve the breadcrumbs

3. Add a generate section to the [main.go](docGen/main.go) to call your new generator

4. If you have acronyms or words like `GitHub` which should be written in a particular casing, check out `func Nicify(input string) string` in [util/util.go](docGen/util/util.go) which handles this. Feel free to add your capitalisations or special cases here.

5. Look at what you've done - once `md-generate` `make` target has run, [avd-repo/content](avd-repo/content) will have the generate Markdown files that Hugo is going to use to generate the content.

### Building Locally

> **A note on updated CSS** - Updating the CSS should be done by changing the the scss files and then running `make compile-theme-sass` to generate the new CSS files

NVD generation takes a lifetime to run, and for the most part it is totally needless to generate locally. My advise is to set `firstYear` in [main.go](docGen/main.go) to `9999` so it doesn't do them - remember to set it back to `1999` before you update though.

Building locally is done by running

```shell
make md-clean md-build sync-all md-generate hugo-generate copy-assets
```

This cleans, build docGen, makes sure all the files are available in `avd-repo`, runs the docGen code, creates the hugo for it, copies the css and html assets over.

### Running Locally

the [README.md](README.md) has a section on using `nginx` to host locally, I didn't find that much fun to use - good luck if you choose to. 

I find the easiest and most reliable (assuming you have `python3` installed) way is

```bash
cd avd-repo/docs
python3 -m http.server
```

This will make the whole site available locally at `http://localhost:8000`

You are unlikely to need to be using search locally, but if you are, the next section should work out for you!!

### Local Search

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

## Daily Build

The daily build is configured in [cron.yml](.github/workflows/cron.yml). 

The process has the following workflow

1. Download the latest repos for source content

2. Runs docGen code to create Markdown

3. Runs Hugo to generate static site and search index

4. Updates the index in the Meilesearch appliance

5. Commits new docs to `githubc.om/aquasecurity/avd`

At this point, gh-pages actions kick in and generate the site.
