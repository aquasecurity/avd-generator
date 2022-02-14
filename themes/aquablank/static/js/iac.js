
function switchTab(tabGroup, tabId) {




    allTabItems = jQuery("[data-tab-group='" + tabGroup + "']");
    targetTabItems = jQuery("[data-tab-group='" + tabGroup + "'][data-tab-item='" + tabId + "']");

    // if event is undefined then switchTab was called from restoreTabSelection
    // so it's not a button event and we don't need to safe the selction or
    // prevent page jump
    var isButtonEvent = event != undefined;

    if (isButtonEvent) {
        // save button position relative to viewport
        var yposButton = event.target.getBoundingClientRect().top;
    }

    allTabItems.removeClass("active");
    targetTabItems.addClass("active");

    if (isButtonEvent) {
        // reset screen to the same position relative to clicked button to prevent page jump
        var yposButtonDiff = event.target.getBoundingClientRect().top - yposButton;
        window.scrollTo(window.scrollX, window.scrollY + yposButtonDiff);

        // Store the selection to make it persistent
        if (window.localStorage) {
            var selectionsJSON = window.localStorage.getItem("tabSelections");
            if (selectionsJSON) {
                var tabSelections = JSON.parse(selectionsJSON);
            } else {
                var tabSelections = {};
            }
            tabSelections[tabGroup] = tabId;
            window.localStorage.setItem("tabSelections", JSON.stringify(tabSelections));
        }
    }

    window.location.hash = tabId;
}

function restoreTabSelections() {
    if (window.localStorage) {
        var selectionsJSON = window.localStorage.getItem("tabSelections");
        if (selectionsJSON) {
            var tabSelections = JSON.parse(selectionsJSON);
        } else {
            var tabSelections = {};
        }
        Object.keys(tabSelections).forEach(function (tabGroup) {
            var tabItem = tabSelections[tabGroup];
            switchTab(tabGroup, tabItem);
        });
    };
}

jQuery(document).ready(function ($) {

    const ids = new Map();

    ids.set('cli', 'CLI')
    ids.set('cloudformation', 'CloudFormation')
    ids.set('dockerfile', 'Dockerfile')
    ids.set('kubernetes', 'Kubernetes')
    ids.set('management console', 'Management Console')
    ids.set('terraform', 'Terraform')

    tabName = document.location.hash.substring(1);
    if (tabName) {
        tabName = ids.get(tabName);
        switchTab('remediation', tabName);
    }






    // //hide list items after x items
    // if ($(".vulnerability_content ul").length) {
    //     $(".vulnerability_content ul").each(function () {
    //         var max_items = 8;
    //         var list_length = $(this).find("li").length;
    //         if (list_length > max_items) {
    //             $(this)
    //                 .find('li:gt(' + max_items + ')')
    //                 .hide()
    //                 .end()
    //                 .append(
    //                     $('<li class="list_more_link">Show ' + (list_length - max_items) + ' more</li>').click(function () {
    //                         $(this).siblings(':hidden').show().end().remove();
    //                     })
    //                 );
    //         };

    //     });
    // }; //if

    // function toggleIacFilter(evt) {
    //     element = $('#iac-filter ul');
    //     if (element.hasClass('visible')) {
    //         element.removeClass('visible');

    //     }
    //     else {
    //         element.addClass('visible');
    //     }
    // }

    // function applyIacMenuFilter() {
    //     // hide the drop down

    //     $('.menu-treeview .node').hide();
    //     $('#iac-filter  input:checked').each(function () {
    //         $('.menu-treeview .' + this.id).show();
    //     });

    // }

    // $('#iac-filter .anchor').click(toggleIacFilter);
    // $('#iac-filter-apply').click(function (evt) {
    //     toggleIacFilter(evt);
    //     applyIacMenuFilter();
    //     $('.menu-treeview > details:visible').attr('open', $('.menu-treeview > details:visible').length == 1);
    // });



    // var checkboxValues = JSON.parse(localStorage.getItem('iacChecksFilter')) || {};
    // var $checkboxes = $("#iac-filter :checkbox");

    // $checkboxes.on("change", function () {
    //     $checkboxes.each(function () {
    //         checkboxValues[this.id] = this.checked;
    //     });
    //     localStorage.setItem("checkboxValues", JSON.stringify(checkboxValues));
    // });

    // $.each(checkboxValues, function (key, value) {
    //     $("#" + key).prop('checked', value);
    // });

    // applyIacMenuFilter();
    // $(".menu-treeview a[href*='" + location.pathname + "']").addClass("menu-treeview-current");
});