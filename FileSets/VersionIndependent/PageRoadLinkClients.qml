import QtQuick 2
import com.victron.velib 1.0

MbPage {
    title: qsTr("Fahrzeuggeraete")
    model: VisibleItemModel {
        MbItemValue { description: qsTr("Verbunden"); item.bind: "com.coyodude.roadlink/Clients/Count" }
        MbItemValue { description: qsTr("Letzte Aktion"); item.bind: "com.coyodude.roadlink/Clients/Status"; show: item.valid && item.value !== "" }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/0/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 0 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/1/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 1 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/2/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 2 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/3/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 3 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/4/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 4 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/5/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 5 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/6/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 6 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/7/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 7 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/8/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 8 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/9/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 9 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/10/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 10 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/11/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 11 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/12/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 12 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/13/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 13 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/14/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 14 } }
        }
        MbSubMenu {
            property VBusItem titleItem: VBusItem { bind: "com.coyodude.roadlink/Clients/15/Title" }
            description: titleItem.value !== undefined && titleItem.value !== null ? String(titleItem.value) : ""
            show: titleItem.value !== undefined && titleItem.value !== null && String(titleItem.value) !== ""
            subpage: Component { PageRoadLinkClient { index: 15 } }
        }
        MbItemText { text: qsTr("Geraete hinter einem Repeater erscheinen mit dessen Ersatz-MAC") }
    }
}
