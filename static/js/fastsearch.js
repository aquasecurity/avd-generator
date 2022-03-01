// Based on https://gist.github.com/cmod/5410eae147e4318164258742dd053993#staticjsfastsearchjs


var meilisearch;
var meilisearchIndex;
var searchVisible = true;
var firstRun = true; // allow us to delay loading json data unless search activated
var list = document.getElementById('search_results_list'); // targets the <ul>
var first = list.firstChild; // first child of search list
var last = list.lastChild; // last child of search list
var maininput = document.getElementById('searchInput'); // input box for search
var resultsAvailable = false; // Did we get any search results?
var base_url = window.location.origin;
var path_name = window.location.pathname;


// ==========================================
// The main keyboard event listener running the show
//
document.addEventListener('keydown', function (event) {

    if (firstRun) {
        loadMeiliSearch();
        firstRun = false; // let's never do this again
    }

    // DOWN (40) arrow
    if (event.keyCode == 40) {
        if (searchVisible && resultsAvailable) {
            console.log("down");
            event.preventDefault(); // stop window from scrolling
            if (document.activeElement == maininput) {
                first.focus();
            } // if the currently focused element is the main input --> focus the first <li>
            else if (document.activeElement == last) {
                last.focus();
            } // if we're at the bottom, stay there
            else {
                document.activeElement.parentElement.nextSibling.firstElementChild.focus();
            } // otherwise select the next search result
        }
    }

    // UP (38) arrow
    if (event.keyCode == 38) {
        if (searchVisible && resultsAvailable) {
            event.preventDefault(); // stop window from scrolling
            if (document.activeElement == maininput) {
                maininput.focus();
            } // If we're in the input box, do nothing
            else if (document.activeElement == first) {
                maininput.focus();
            } // If we're at the first item, go to input box
            else {
                document.activeElement.parentElement.previousSibling.firstElementChild.focus();
            } // Otherwise, select the search result above the current active one
        }
    }
});


// execute on every keystroke
document.getElementById("searchInput").onkeyup = function (e) {
    executeSearch(this.value);
}

// ==========================================
// load our search index, only executed once
// host: search endpoint
// apiKey: read-only public secret: https://docs.meilisearch.com/reference/features/authentication.html#key-types
function loadMeiliSearch() {
    meilisearch = new MeiliSearch({
        host: 'https://avdsearch.aquasec.com',
        apiKey: "d182155a23f2f0acaafbb882a68cbd0080a5b1a47749712d4b704dad03899303", // this is a read-only public key, *not a secret*
    })
    meilisearchIndex = meilisearch.getIndex('avd');
}

// ==========================================
// a search query (for "term") every time a letter is typed
// in the search box
//
async function executeSearch(term) {
    let results = await meilisearchIndex.search(term, { attributesToHighlight: '*' });
    let searchitems = ''; // our results bucket

    if (results.length === 0) { // no results based on what was typed into the input box
        resultsAvailable = false;
        searchitems = '';
    } else { // build our html
        for (let item in results.hits.slice(0, 10)) { // only show first 10 results
            searchitems = searchitems +
                '<li><a href="'
                + results.hits[item].permalink
                + '" tabindex="0">'
                + '<span class="result_title">'
                + results.hits[item].pageTitle
                + '</span><br />'
                + results.hits[item]._formatted.summary
                + '</a>'
                + '</li>';
        }
        resultsAvailable = true;
    }

    document.getElementById("search_results_list").innerHTML = searchitems;
    if (results.length > 0) {
        first = list.firstChild.firstElementChild; // first result container — used for checking against keyboard up/down location
        last = list.lastChild.firstElementChild; // last result container — used for checking against keyboard up/down location
    }
}
